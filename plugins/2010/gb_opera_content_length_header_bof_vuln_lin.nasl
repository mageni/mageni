###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_content_length_header_bof_vuln_lin.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Opera Browser 'Content-Length' Header Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801318");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-1349");
  script_bugtraq_id(38519);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Opera Browser 'Content-Length' Header Buffer Overflow Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38820");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11622");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0529");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Mar/1023690.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash an affected browser
  or execute arbitrary code.");
  script_tag(name:"affected", value:"Opera version 10.10 on Linux.");
  script_tag(name:"insight", value:"The flaw is due to a buffer overflow error when processing malformed
  HTTP 'Content-Length:' headers.");
  script_tag(name:"solution", value:"Upgrade to Opera version 10.53 or later.");
  script_tag(name:"summary", value:"The host is installed with Opera Web Browser and is prone to
  buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.opera.com/browser/download/");
  exit(0);
}


include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_equal(version:operaVer, test_version:"10.10")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
