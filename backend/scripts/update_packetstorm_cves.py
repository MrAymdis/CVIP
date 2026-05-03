#!/usr/bin/env python3
"""
Update CVE records that were created by packetstorm crawler but have no published date.
Fetch details from NVD API and update database.
"""
import httpx
import asyncio
from datetime import datetime
from sqlalchemy.orm import Session
