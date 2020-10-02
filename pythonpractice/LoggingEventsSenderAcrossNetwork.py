import logging, logging.handlers

rootLogger = logging.getLogger('');
rootLogger.setLevel(logging.DEBUG)
socketHandler = logging.handlers.SocketHandler('localhost', logging.handlers.DEFAULT_TCP_LOGGING_PORT)

#don't bother with a formatter , since a socket handler sends the event as an unformatted pickle
logging.info('Jackdaws love my big sphnix of quartz')

# Now define a couple of other loggers which might represent areas in your application:

logger1 = logging.getLogger('myapp.area1')
logger2 = logging.getLogger('myapp.area2')

logger1.debug('Quick zephyrs blow, vexing daft Jim.')
logger1.info('How quickly daft jumping zebras vex.')
logger2.warning('Jail zesty zixen')
logger2.error('The five boxing wizards jump quickly.')




