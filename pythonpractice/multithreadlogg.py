import logging
import threading
import time

def worker(arg):
       while not arg['stop']:
            logging.debug("Hi from myfunc")
            time.sleep(0.5)
       
def main():

       logging.basicConfig(level=logging.DEBUG, format='%(relativeCreated)6d %(threadName)s %(message)s')
       info = {'stop': False}
       thread = threading.Thread(target=worker, args=(info,))
       thread.start()            

       
