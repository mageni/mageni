###############################################################################
# OpenVAS Vulnerability Test
#
# Sun Java System Web Proxy Server Vulnerabilities (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800025");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2008-10-16 18:25:33 +0200 (Thu, 16 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4541");
  script_bugtraq_id(31691);
  script_name("Sun Java System Web Proxy Server Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32227");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45782");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2781");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-242986-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl", "gb_get_http_banner.nasl");
  script_mandatory_keys("Sun-Java-System-Web-Proxy-Server/banner", "SMB/WindowsVersion");
  script_require_ports("Services/www", 8081, 139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary code in the context
  of the server, and failed attacks may cause denial-of-service condition.");

  script_tag(name:"affected", value:"Sun Java System Web Proxy Server versions prior to 4.0.8 on all running platform.");

  script_tag(name:"insight", value:"The flaw exists due to a boundary error in the FTP subsystem and in processing
  HTTP headers. This issue resides within the code responsible for handling HTTP GET requests.");

  script_tag(name:"summary", value:"This host has Sun Java Web Proxy Server running, which is prone
  to heap buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Update to version 4.0.8 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("http_func.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

sunPort = get_http_port(default:8081);

banner = get_http_banner(port:sunPort);
if(!banner){
  exit(0);
}
if(banner =~ "Server: Sun-Java-System-Web-Proxy-Server/[0-3]\.0")
{
  security_message(sunPort);
  exit(0);
}

if(banner =~ "Server: Sun-Java-System-Web-Proxy-Server/4\.0")
{
  proxyVer = registry_enum_keys(key:"SOFTWARE\Sun Microsystems\ProxyServer");
  if(proxyVer == NULL){
    exit(0);
  }

  if(version_in_range(version:proxyVer[0], test_version:"4.0", test_version2:"4.0.7")){
    security_message(sunPort);
  }
}
