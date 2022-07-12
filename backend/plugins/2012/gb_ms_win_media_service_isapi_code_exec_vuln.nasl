###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Media Services ISAPI Extension Code Execution Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802897");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2003-0227", "CVE-2003-0349");
  script_bugtraq_id(7727, 8035);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-07-25 16:04:16 +0530 (Wed, 25 Jul 2012)");
  script_name("Microsoft Windows Media Services ISAPI Extension Code Execution Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/9115");
  script_xref(name:"URL", value:"http://secunia.com/advisories/8883");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1007059");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/113716");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms03-019");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms03-022");
  script_xref(name:"URL", value:"http://support.microsoft.com/default.aspx?scid=kb;en-us;822343");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to obtain sensitive
  information, execute arbitrary code or cause denial of service conditions.");
  script_tag(name:"affected", value:"Windows Media Services 4.0 and 4.1

  Microsoft Windows NT 4.0

  Microsoft Windows 2000");
  script_tag(name:"insight", value:"Windows Media Services logging capability for multicast transmissions is
  implemented as ISAPI extension (nsiislog.dll), which fails to processes
  incoming client or malicious HTTP requests.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is running Microsoft Windows Media Services and is prone
  to remote code execution vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

url = "/scripts/nsiislog.dll";
iisreq = http_get(item: url, port: port);
iisres = http_keepalive_send_recv(port:port, data:iisreq, bodyonly:FALSE);

if(!iisres || ">NetShow ISAPI Log Dll" >!< iisres){
  exit(0);
}

postData = crap(data: "A", length: 70000);

host = http_host_name(port:port);

iisreq = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Length: ", strlen(postData),
                "\r\n\r\n", postData);
iisres = http_send_recv(port:port, data:iisreq);

if(iisres && "HTTP/1.1 500 Server Error" >< iisres &&
   "The remote procedure call failed" >< iisres && "<title>Error" >< iisres){
  security_message(port:port);
}
