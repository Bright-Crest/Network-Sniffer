import logging

from net_proj import settings

SSE_URL = "events/"
SSE_CHANNELS = ["switch"]

LOG_LEVEL = logging.WARNING
logging.basicConfig(level=LOG_LEVEL, format = '%(asctime)s %(name)s: [%(levelname)s] %(message)s')
