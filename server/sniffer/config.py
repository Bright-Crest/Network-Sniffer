import logging

from net_proj import settings

SSE_URL = "events/"
SSE_CHANNELS = ["switch"]

logging.basicConfig(level=logging.DEBUG if settings.DEBUG else logging.INFO, format = '%(asctime)s %(name)s: [%(levelname)s] %(message)s')
