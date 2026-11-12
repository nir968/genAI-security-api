"""The declarative base shared by every table.

It lives in its own module so that ``main`` (request_logs) and
``mcp_security`` (mcp_events, mcp_approvals) can both register tables on it
without importing each other. ``Base.metadata.create_all`` at startup then
creates all of them.
"""
from sqlalchemy.orm import declarative_base

Base = declarative_base()
