#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/time.h>


#define DEVICE_NAME "mytraffic"
#define STATIC_MAJOR 61


// Timer structure
struct my_timer_info {
    struct timer_list timer;
    pid_t user_pid;
    char user_msg[MAX_MSG_LEN];
    char user_cmd[TASK_COMM_LEN];
    unsigned long expiration_jiffies;
    int active;
};

static struct my_timer_info timers[MAX_TIMERS];
static unsigned long module_start_jiffies;
static char update_response[256] = {0};  // Response for timer updates
static int mode = 1; //Operational Mode. 1: Normal 2: Flashing-Red 3: Flashing-Yellow
static int cycle_length = 1; //Cycle Length
static int red = 1; //Red Light Status. 1: ON 0: OFF
static int yellow = 0; //Yellow Light Status. 1: ON 0: OFF
static int green = 0; //Green Light Status. 1: ON 0: OFF
static int pedestrian = 0; //Pedestrian Status. 1: Present 0: NOT Present

static int gpio_red = 67;      
static int gpio_yellow = 68;   
static int gpio_green = 69;    
static int gpio_btn0 = 26;     //  (mode switch)
static int gpio_btn1 = 27;     //  (pedestrian)
module_param(gpio_red, int, 0444);
module_param(gpio_yellow, int, 0444);
module_param(gpio_green, int, 0444);
module_param(gpio_btn0, int, 0444);
module_param(gpio_btn1, int, 0444);


/* Button IRQ handlers (edges) */
static irqreturn_t btn0_isr(int irq, void *dev_id)
{
    unsigned long now = jiffies;
    if (time_before(now, last_btn0_jiffies + msecs_to_jiffies(DEBOUNCE_MS)))
        return IRQ_HANDLED;
    last_btn0_jiffies = now;

    /* Cycle modes */
    mutex_lock(&state_lock);
    if (cur_mode == MODE_NORMAL) cur_mode = MODE_FLASH_RED;
    else if (cur_mode == MODE_FLASH_RED) cur_mode = MODE_FLASH_YELLOW;
    else cur_mode = MODE_NORMAL;
    mutex_unlock(&state_lock);
    return IRQ_HANDLED;
}

static irqreturn_t btn1_isr(int irq, void *dev_id)
{
    unsigned long now = jiffies;
    if (time_before(now, last_btn1_jiffies + msecs_to_jiffies(DEBOUNCE_MS)))
        return IRQ_HANDLED;
    last_btn1_jiffies = now;

    mutex_lock(&state_lock);
    /* Only register pedestrian request if in normal mode */
    if (cur_mode == MODE_NORMAL) {
        pedestrian_requested = true;
    }
    mutex_unlock(&state_lock);

    return IRQ_HANDLED;
}

static int traffic_thread_fn(void *data)
{
    while (!kthread_should_stop()) {
        int local_hz;
        enum mode_t local_mode;
        bool local_pedestrian;

        /* Snapshot state */
        mutex_lock(&state_lock);
        local_hz = cycle_hz;
        local_mode = cur_mode;
        local_pedestrian = pedestrian_requested;
        mutex_unlock(&state_lock);

        if (local_hz < 1) local_hz = 1;
        if (local_hz > 9) local_hz = 9;

        /* cycle length in ms */
        unsigned int cycle_ms = 1000 / local_hz;

        if (local_mode == MODE_NORMAL) {
            /* Normal: green 3 cycles, yellow 1 cycle, red 2 cycles,
               BUT if pedestrian_requested then next stop phase (red) becomes red+yellow for 5 cycles. */
            int i;

            /* GREEN for 3 cycles */
            for (i = 0; i < 3; ++i) {
                set_leds(false, false, true);
                if (kthread_should_stop()) goto out;
                msleep(cycle_ms);
            }

            /* YELLOW for 1 cycle */
            set_leds(false, true, false);
            if (kthread_should_stop()) goto out;
            msleep(cycle_ms);

            /* RED or RED+YELLOW stop phase */
            mutex_lock(&state_lock);
            bool do_ped = pedestrian_requested;
            if (do_ped) pedestrian_requested = false; /* consume */
            mutex_unlock(&state_lock);

            if (do_ped) {
                /* Massachusetts-style "stop": both red+yellow for 5 cycles */
                for (i = 0; i < 5; ++i) {
                    set_leds(true, true, false);
                    if (kthread_should_stop()) goto out;
                    msleep(cycle_ms);
                }
            } else {
                /* RED for 2 cycles */
                for (i = 0; i < 2; ++i) {
                    set_leds(true, false, false);
                    if (kthread_should_stop()) goto out;
                    msleep(cycle_ms);
                }
            }
        } else if (local_mode == MODE_FLASH_RED) {
            /* flash red 1 cycle on, 1 cycle off continuously */
            set_leds(true, false, false);
            if (kthread_should_stop()) break;
            msleep(cycle_ms);
            set_leds(false, false, false);
            if (kthread_should_stop()) break;
            msleep(cycle_ms);
        } else if (local_mode == MODE_FLASH_YELLOW) {
            /* flash yellow 1 cycle on, 1 cycle off continuously */
            set_leds(false, true, false);
            if (kthread_should_stop()) break;
            msleep(cycle_ms);
            set_leds(false, false, false);
            if (kthread_should_stop()) break;
            msleep(cycle_ms);
        } else {
            /* unknown mode: sleep briefly */
            set_leds(false, false, false);
            msleep(200);
        }
    }

out:
    /* Ensure lights off on thread stop */
    set_leds(false, false, false);
    return 0;
}

// Forward declarations
static ssize_t mytraffic_read(struct file *file, char __user *buf, size_t len, loff_t *offset);
static ssize_t mytraffic_write(struct file *file, const char __user *buf, size_t len, loff_t *offset);
static int mytraffic_open(struct inode *inode, struct file *file);
static int mytraffic_release(struct inode *inode, struct file *file);

// File operations
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = mytraffic_read,
    .write = mytraffic_write,
    .open = mytraffic_open,
};

// Timer callback
void timer_callback(struct timer_list *t) {
    int i;
    
    // Find which timer expired
    for (i = 0; i < MAX_TIMERS; i++) {
        if (&timers[i].timer == t && timers[i].active) {
            if (timers[i].async_queue)
                kill_fasync(&timers[i].async_queue, SIGIO, POLL_IN);

            // Clear the expired timer
            timers[i].active = 0;
            timers[i].user_pid = 0;
            timers[i].user_msg[0] = '\0';
            timers[i].user_cmd[0] = '\0';
            break;
        }
    }
}

// Character device open
static int mytraffic_open(struct inode *inode, struct file *file) {
    return 0;
}

// Character device read
static ssize_t mytraffic_read(struct file *file, char __user *buf, size_t len, loff_t *offset) {
    char response[256] = {0};
    size_t response_len = 0;
    int i;
    
    if (*offset > 0) return 0; // EOF
    
    response_len = snprintf(response, sizeof(response), 
                            "[MODE]: %s\n"
                            "[RATE]: %dHz\n"
                            "[RED]: %s\n"
                            "[YELLOW]: %s\n"
                            "[GREEN]: %s\n"
                            "[PEDESTRIAN]: %s\n",
                            mode == 1 ? "Normal" : mode == 2 ? "Flashing-Red" : mode == 3 ? "Flashing-Yellow" : "Invalid",
                            cycle_length,
                            red == 1 ? "ON" : "OFF",
                            yellow == 1 ? "ON" : "OFF",
                            green == 1 ? "ON" : "OFF",
                            pedestrian == 1 ? "Present" : "NOT Present");
    
    if (copy_to_user(buf, response, len)) return -EFAULT;
    
    *offset += len;
    return len;
}

static ssize_t mytraffic_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos)
{
    char kbuf[32];
    long val;
    int ret;

    if (count == 0 || count >= sizeof(kbuf))
        return count; /* ignore nonsense */

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;
    kbuf[count] = '\0';

    ret = kstrtol(kbuf, 10, &val);
    if (ret != 0) {
        /* ignore non-integers silently as requested */
        return count;
    }

    if (val < 1 || val > 9) {
        /* ignore out-of-range silently */
        return count;
    }

    mutex_lock(&state_lock);
    cycle_hz = (int)val;
    mutex_unlock(&state_lock);

    return count;
}


static int __init mytraffic_init(void) {
    int ret;

    pr_info("mytraffic: init (red=%d,yellow=%d,green=%d,btn0=%d,btn1=%d)\n",
            gpio_red, gpio_yellow, gpio_green, gpio_btn0, gpio_btn1);

    /* Validate cycle_hz */
    if (cycle_hz < 1) cycle_hz = 1;
    if (cycle_hz > 9) cycle_hz = 9;

    /* Request GPIOs for LEDs */
    if (gpio_request(gpio_red, "mytraffic_red")) {
        pr_err("mytraffic: failed to request gpio %d (red)\n", gpio_red);
        ret = -EBUSY; goto fail;
    }
    if (gpio_request(gpio_yellow, "mytraffic_yellow")) {
        pr_err("mytraffic: failed to request gpio %d (yellow)\n", gpio_yellow);
        ret = -EBUSY; goto free_red;
    }
    if (gpio_request(gpio_green, "mytraffic_green")) {
        pr_err("mytraffic: failed to request gpio %d (green)\n", gpio_green);
        ret = -EBUSY; goto free_yellow;
    }

    /* Set as outputs and turn off initially */
    gpio_direction_output(gpio_red, 0);
    gpio_direction_output(gpio_yellow, 0);
    gpio_direction_output(gpio_green, 0);

    /* Request button GPIOs */
    if (gpio_request(gpio_btn0, "mytraffic_btn0")) {
        pr_err("mytraffic: failed to request gpio %d (btn0)\n", gpio_btn0);
        ret = -EBUSY; goto free_green;
    }
    if (gpio_direction_input(gpio_btn0)) {
        pr_warn("mytraffic: warning: gpio_direction_input failed for btn0\n");
    }
    if (gpio_request(gpio_btn1, "mytraffic_btn1")) {
        pr_err("mytraffic: failed to request gpio %d (btn1)\n", gpio_btn1);
        ret = -EBUSY; goto free_btn0;
    }
    if (gpio_direction_input(gpio_btn1)) {
        pr_warn("mytraffic: warning: gpio_direction_input failed for btn1\n");
    }

    /* Map button gpio to IRQs */
    irq_btn0 = gpio_to_irq(gpio_btn0);
    if (irq_btn0 < 0) {
        pr_err("mytraffic: gpio_to_irq failed for btn0\n");
        ret = irq_btn0; goto free_btn1;
    }
    irq_btn1 = gpio_to_irq(gpio_btn1);
    if (irq_btn1 < 0) {
        pr_err("mytraffic: gpio_to_irq failed for btn1\n");
        ret = irq_btn1; goto free_btn1;
    }

    /* Request IRQs on falling or rising edges (use both edges to catch presses/releases depending on wiring) */
    ret = request_irq(irq_btn0, btn0_isr, IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING, "mytraffic_btn0", NULL);
    if (ret) {
        pr_err("mytraffic: request_irq failed for btn0\n");
        goto free_btn1;
    }
    ret = request_irq(irq_btn1, btn1_isr, IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING, "mytraffic_btn1", NULL);
    if (ret) {
        pr_err("mytraffic: request_irq failed for btn1\n");
        free_irq(irq_btn0, NULL);
        goto free_btn1;
    }

    /* Start traffic thread */
    traffic_thread = kthread_run(traffic_thread_fn, NULL, "mytraffic_thread");
    if (IS_ERR(traffic_thread)) {
        pr_err("mytraffic: failed to create traffic thread\n");
        ret = PTR_ERR(traffic_thread);
        free_irq(irq_btn1, NULL);
        free_irq(irq_btn0, NULL);
        goto free_btn1;
    }

    if (register_chrdev(STATIC_MAJOR, DEVICE_NAME, &fops) < 0) {
        pr_err("Failed to register device with major %d\n", STATIC_MAJOR);
        return -EBUSY;
    }

    pr_info("Traffic module loaded, major=%d\n", STATIC_MAJOR);

    return 0;
}

static void __exit mytraffic_exit(void) {
    int i;

    /* Stop thread */
    if (traffic_thread) kthread_stop(traffic_thread);

    /* Free IRQs */
    if (irq_btn1 >= 0) free_irq(irq_btn1, NULL);
    if (irq_btn0 >= 0) free_irq(irq_btn0, NULL);
    
    unregister_chrdev(STATIC_MAJOR, DEVICE_NAME);
    printk(KERN_INFO "mytraffic module unloaded\n");

    /* Turn off LEDs */
    set_leds(false, false, false);

    /* Free GPIOs */
    gpio_free(gpio_btn1);
    gpio_free(gpio_btn0);
    gpio_free(gpio_green);
    gpio_free(gpio_yellow);
    gpio_free(gpio_red);
}

module_init(mytraffic_init);
module_exit(mytraffic_exit);