###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winftp_serv_bof_vuln.nasl 12676 2018-12-05 15:27:20Z cfischer $
#
# WinFTP Server LIST Command Buffer Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800346");
  script_version("$Revision: 12676 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:27:20 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-02-04 15:43:54 +0100 (Wed, 04 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0351");
  script_bugtraq_id(33454);
  script_name("WinFTP Server LIST Command Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_winftp_serv_detect.nasl");
  script_mandatory_keys("WinFTP/Server/Ver");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7875");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48263");

  script_tag(name:"impact", value:"Allows remote authenticated attackers to execute arbitrary code within the
  context of the affected application resulting in buffer overflow and can cause
  denial of service condition.");

  script_tag(name:"affected", value:"WinFTP Server version 2.3.0 and prior on Windows.");

  script_tag(name:"insight", value:"The flaw exists when processing malformed arguments passed to the LIST command
  with an asterisk (*) character.");

  script_tag(name:"solution", value:"Upgrade to WinFTP Server version 3.5.0 or later.");

  script_tag(name:"summary", value:"This host is running WinFTP Server and is prone to Buffer Overflow
  vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

winFtpVer = get_kb_item("WinFTP/Server/Ver");
if(!winFtpVer) exit(0);

if(version_is_less_equal(version:winFtpVer, test_version:"2.3.0.0")){
  security_message(port:0);
}

exit(0);