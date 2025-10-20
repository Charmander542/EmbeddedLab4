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
#define DEBOUNCE_MS 200


static int mode = 1; //Operational Mode. 1: Normal 2: Flashing-Red 3: Flashing-Yellow
static int cycle_length = 1; //Cycle Length
static unsigned int cycle_counter = 0; //Counter for cycles
static int red = 1; //Red Light Status. 1: ON 0: OFF
static int yellow = 0; //Yellow Light Status. 1: ON 0: OFF
static int green = 0; //Green Light Status. 1: ON 0: OFF
static int pedestrian = 0; //Pedestrian Status. 1: Present 0: NOT Present

static int last_btn0_jiffies = 0;
static int last_btn1_jiffies = 0;

static int gpio_red = 67;      
static int gpio_yellow = 68;   
static int gpio_green = 44;    
static int gpio_btn0 = 26;     //  (mode switch)
static int gpio_btn1 = 46;     //  (pedestrian)

/* gpio descriptors */
static struct gpio_desc *gdesc_green;
static struct gpio_desc *gdesc_yellow;
static struct gpio_desc *gdesc_red;
static struct gpio_desc *gdesc_btn_0;
static struct gpio_desc *gdesc_btn_1;

/* IRQ number for button */
static int btn0_irq = -1;
static int btn1_irq = -1;


/* Button IRQ handlers (edges) */
static irqreturn_t btn0_isr(int irq, void *dev_id)
{
    unsigned long now = jiffies;
    if (time_before(now, last_btn0_jiffies + msecs_to_jiffies(DEBOUNCE_MS)))
        return IRQ_HANDLED;
    last_btn0_jiffies = now;

    /* Cycle modes */
    mutex_lock(&state_lock);
    cycle_counter = 0;
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

static void set_leds(bool red_on, bool yellow_on, bool green_on) {
    gpio_set_value(gdesc_red, red_on ? 1 : 0);
    gpio_set_value(gdesc_yellow, yellow_on ? 1 : 0);
    gpio_set_value(gdesc_green, green_on ? 1 : 0);
}

static void update_traffic_lights(void) {
    mutex_lock(&state_lock);
    unsigned int idx;
    bool g = false, y = false, r = false;

    switch (cur_mode) {
    case MODE_NORMAL:
        idx = cycle_counter % 6; // 3 green, 1 yellow, 2 red
        if (idx <= 2) g = true;
        else if (idx == 3) y = true;
        else r = true;
        break;
    case MODE_FLASH_RED:
        r = (cycle_counter & 1) ? true : false;
        break;
    case MODE_FLASH_YELLOW:
        y = (cycle_counter & 1) ? true : false;
        break;
    }

    set_leds(r, y, g);
    mutex_unlock(&state_lock);
}

static void timer_cb(struct timer_list *t) {
    cycle_counter++;
    update_traffic_lights();

    /* Restart timer */
    mod_timer(&tick_timer, jiffies + msecs_to_jiffies(1000 / cycle_length));
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
    cycle_length = (int)val;
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
    gdesc_green = gpio_to_desc(gpio_green);
    gdesc_yellow = gpio_to_desc(gpio_yellow);
    gdesc_red = gpio_to_desc(gpio_red);

    /* Set as outputs and turn off initially */
    gpiod_direction_output(gdesc_green, 0);
    gpiod_direction_output(gdesc_yellow, 0);
    gpiod_direction_output(gdesc_red, 0);

    gdesc_btn_0 = gpio_to_desc(gpio_btn0);
    gdesc_btn_1 = gpio_to_desc(gpio_btn1);

    gpiod_direction_input(gdesc_btn_0);
    gpiod_direction_input(gdesc_btn_1);

    btn0_irq = gdesc_to_irq(gdesc_btn_0);
    btn1_irq = gdesc_to_irq(gdesc_btn_1);

    /* Request IRQs for buttons */
    request_irq(btn0_irq, btn0_isr,
                IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING,
                "mytraffic_btn0", NULL);

    request_irq(btn1_irq, btn1_isr,
                IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING,
                "mytraffic_btn1", NULL);

    if (register_chrdev(STATIC_MAJOR, DEVICE_NAME, &fops) < 0) {
        pr_err("Failed to register device with major %d\n", STATIC_MAJOR);
        return -EBUSY;
    }

    spin_lock_irq(&state_lock);
    cur_mode = MODE_NORMAL;
    cycle_counter = 0;
    update_lights_locked();
    spin_unlock_irq(&state_lock);

    pr_info("Traffic module loaded, major=%d\n", STATIC_MAJOR);

    return 0;
}

static void __exit mytraffic_exit(void) {
    int i;

    /* Free IRQs */
    if (btn1_irq >= 0) free_irq(btn1_irq, NULL);
    if (btn0_irq >= 0) free_irq(btn0_irq, NULL);

    del_timer_sync(&tick_timer);
    
    unregister_chrdev(STATIC_MAJOR, DEVICE_NAME);
    printk(KERN_INFO "mytraffic module unloaded\n");

    /* Turn off LEDs */
    set_leds(false, false, false);

    /* Free GPIOs */
    gpiod_put(gdesc_green);
    gpiod_put(gdesc_yellow);
    gpiod_put(gdesc_red);
    gpiod_put(gdesc_btn_0);
    gpiod_put(gdesc_btn_1);
}

module_init(mytraffic_init);
module_exit(mytraffic_exit);