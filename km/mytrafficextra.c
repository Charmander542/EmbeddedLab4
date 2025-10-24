#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/timer.h>
#include <linux/jiffies.h>

#define DEVICE_NAME "mytraffic"
#define STATIC_MAJOR 61
#define DEBOUNCE_MS 200

#define MODE_NORMAL       1
#define MODE_FLASH_RED    2
#define MODE_FLASH_YELLOW 3

static int cur_mode = MODE_NORMAL;
static int cycle_hz = 1;
static unsigned int cycle_counter = 0;
static bool pedestrian_requested = false;
static bool pedestrian_stop_active = false;
static unsigned int pedestrian_stop_counter = 0;
static bool btn0_pressed = false;
static bool btn1_pressed = false;
static bool lightbulb_check_active = false;

static DEFINE_MUTEX(state_lock);
static struct timer_list tick_timer;

static unsigned long last_btn0_jiffies = 0;
static unsigned long last_btn1_jiffies = 0;

static int gpio_red = 67;
static int gpio_yellow = 68;
static int gpio_green = 44;
static int gpio_btn0 = 26;
static int gpio_btn1 = 46;

static int irq_btn0 = -1;
static int irq_btn1 = -1;

static void set_leds(bool red_on, bool yellow_on, bool green_on)
{
    gpio_set_value(gpio_red, red_on ? 1 : 0);
    gpio_set_value(gpio_yellow, yellow_on ? 1 : 0);
    gpio_set_value(gpio_green, green_on ? 1 : 0);
}

static void check_button_states(void)
{
    bool btn0_current = gpio_get_value(gpio_btn0);
    bool btn1_current = gpio_get_value(gpio_btn1);
    
    mutex_lock(&state_lock);
    
    // Check for lightbulb check mode (both buttons pressed)
    if (btn0_current && btn1_current) {
        if (!lightbulb_check_active) {
            lightbulb_check_active = true;
        }
    }
    // Check for reset (both buttons released after being pressed)
    else if (!btn0_current && !btn1_current) {
        if (lightbulb_check_active) {
            // Reset to initial state
            lightbulb_check_active = false;
            cur_mode = MODE_NORMAL;
            cycle_hz = 1;
            cycle_counter = 0;
            pedestrian_requested = false;
            pedestrian_stop_active = false;
            pedestrian_stop_counter = 0;
        }
    }
    
    btn0_pressed = btn0_current;
    btn1_pressed = btn1_current;
    
    mutex_unlock(&state_lock);
}

static void update_traffic_lights(void)
{
    unsigned int idx;
    bool r = false, y = false, g = false;

    mutex_lock(&state_lock);
    
    // Lightbulb check mode - all lights on
    if (lightbulb_check_active) {
        r = y = g = true;
    }
    // Pedestrian stop phase - red and yellow for 5 cycles
    else if (pedestrian_stop_active) {
        r = y = true;
        g = false;
    }
    // Normal traffic light patterns
    else {
        switch (cur_mode) {
        case MODE_NORMAL:
            idx = cycle_counter % 6;
            if (idx <= 2)
                g = true;
            else if (idx == 3)
                y = true;
            else
                r = true;
            break;
        case MODE_FLASH_RED:
            r = (cycle_counter & 1);
            break;
        case MODE_FLASH_YELLOW:
            y = (cycle_counter & 1);
            break;
        }
    }
    
    set_leds(r, y, g);
    mutex_unlock(&state_lock);
}

static void timer_cb(struct timer_list *t)
{
    // Check button states for lightbulb check and reset
    check_button_states();
    
    mutex_lock(&state_lock);
    
    // Handle pedestrian stop phase
    if (pedestrian_stop_active) {
        pedestrian_stop_counter++;
        if (pedestrian_stop_counter >= 5) {
            pedestrian_stop_active = false;
            pedestrian_stop_counter = 0;
            pedestrian_requested = false;
        }
    } else {
        cycle_counter++;
        
        // Check if pedestrian request should be activated
        if (pedestrian_requested && cur_mode == MODE_NORMAL && !lightbulb_check_active) {
            unsigned int idx = cycle_counter % 6;
            if (idx == 4) { // Start of red phase
                pedestrian_stop_active = true;
                pedestrian_stop_counter = 0;
            }
        }
    }
    
    mutex_unlock(&state_lock);
    
    update_traffic_lights();
    mod_timer(&tick_timer, jiffies + msecs_to_jiffies(1000 / cycle_hz));
}

static irqreturn_t btn0_isr(int irq, void *dev_id)
{
    unsigned long now = jiffies;
    if (time_before(now, last_btn0_jiffies + msecs_to_jiffies(DEBOUNCE_MS)))
        return IRQ_HANDLED;
    last_btn0_jiffies = now;

    mutex_lock(&state_lock);
    cycle_counter = 0;
    if (cur_mode == MODE_NORMAL)
        cur_mode = MODE_FLASH_RED;
    else if (cur_mode == MODE_FLASH_RED)
        cur_mode = MODE_FLASH_YELLOW;
    else
        cur_mode = MODE_NORMAL;
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
    // Only activate pedestrian call in normal mode
    if (cur_mode == MODE_NORMAL && !pedestrian_stop_active && !lightbulb_check_active) {
        pedestrian_requested = true;
    }
    mutex_unlock(&state_lock);

    return IRQ_HANDLED;
}

static ssize_t mytraffic_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
    char response[256];
    int response_len;

    if (*offset > 0)
        return 0;

    response_len = snprintf(response, sizeof(response),
                            "[MODE]: %s\n"
                            "[RATE]: %dHz\n"
                            "[PEDESTRIAN]: %s\n"
                            "[PEDESTRIAN_STOP]: %s\n"
                            "[LIGHTBULB_CHECK]: %s\n",
                            cur_mode == MODE_NORMAL ? "Normal"
                            : cur_mode == MODE_FLASH_RED ? "Flashing-Red"
                            : cur_mode == MODE_FLASH_YELLOW ? "Flashing-Yellow"
                                                            : "Invalid",
                            cycle_hz,
                            pedestrian_requested ? "Yes" : "No",
                            pedestrian_stop_active ? "Active" : "Inactive",
                            lightbulb_check_active ? "Active" : "Inactive");

    if (copy_to_user(buf, response, response_len))
        return -EFAULT;

    *offset += response_len;
    return response_len;
}

static ssize_t mytraffic_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos)
{
    char kbuf[32];
    long val;
    int ret;

    if (count == 0 || count >= sizeof(kbuf))
        return count;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;
    kbuf[count] = '\0';

    ret = kstrtol(kbuf, 10, &val);
    if (ret != 0)
        return count;

    if (val < 1 || val > 9)
        return count;

    mutex_lock(&state_lock);
    cycle_hz = (int)val;
    mutex_unlock(&state_lock);

    return count;
}

static int mytraffic_open(struct inode *inode, struct file *file) { return 0; }
static int mytraffic_release(struct inode *inode, struct file *file) { return 0; }

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = mytraffic_read,
    .write = mytraffic_write,
    .open = mytraffic_open,
    .release = mytraffic_release,
};

static int __init mytraffic_init(void)
{
    int ret;

    pr_info("mytraffic: init (red=%d,yellow=%d,green=%d,btn0=%d,btn1=%d)\n",
            gpio_red, gpio_yellow, gpio_green, gpio_btn0, gpio_btn1);

    gpio_request(gpio_red, "mytraffic_red");
    gpio_request(gpio_yellow, "mytraffic_yellow");
    gpio_request(gpio_green, "mytraffic_green");
    gpio_direction_output(gpio_red, 0);
    gpio_direction_output(gpio_yellow, 0);
    gpio_direction_output(gpio_green, 0);

    gpio_request(gpio_btn0, "mytraffic_btn0");
    gpio_direction_input(gpio_btn0);
    gpio_request(gpio_btn1, "mytraffic_btn1");
    gpio_direction_input(gpio_btn1);

    irq_btn0 = gpio_to_irq(gpio_btn0);
    irq_btn1 = gpio_to_irq(gpio_btn1);
    request_irq(irq_btn0, btn0_isr, IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING, "mytraffic_btn0", NULL);
    request_irq(irq_btn1, btn1_isr, IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING, "mytraffic_btn1", NULL);

    timer_setup(&tick_timer, timer_cb, 0);
    mod_timer(&tick_timer, jiffies + msecs_to_jiffies(1000 / cycle_hz));

    register_chrdev(STATIC_MAJOR, DEVICE_NAME, &fops);

    pr_info("Traffic module loaded, major=%d\n", STATIC_MAJOR);
    return 0;
}

static void __exit mytraffic_exit(void)
{
    del_timer_sync(&tick_timer);
    free_irq(irq_btn0, NULL);
    free_irq(irq_btn1, NULL);
    unregister_chrdev(STATIC_MAJOR, DEVICE_NAME);

    set_leds(false, false, false);
    gpio_free(gpio_red);
    gpio_free(gpio_yellow);
    gpio_free(gpio_green);
    gpio_free(gpio_btn0);
    gpio_free(gpio_btn1);

    pr_info("mytraffic module unloaded\n");
}

module_init(mytraffic_init);
module_exit(mytraffic_exit);
MODULE_LICENSE("GPL");
