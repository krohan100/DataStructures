import logging
import threading
import time

def worker(arg):
        while not arg['stop']:
              logging.debug('Hi from my function')
              time.sleep(0.5)
              
def main():
            logging.basicConfig(level=logging.DEBUG, format='%(relativeCreated)6d %(threadName)s %(message)s')
            info = {'stop': False}
            
            

