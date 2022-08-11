###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pegasus_mail_pop3_bof_vuln.nasl 14330 2019-03-19 13:59:11Z asteins $
#
# Pegasus Mail POP3 Response Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800970");
  script_version("$Revision: 14330 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:59:11 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3838");
  script_bugtraq_id(36797);
  script_name("Pegasus Mail POP3 Response Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37134");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3026");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Oct/1023075.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_pegasus_mail_detect.nasl");
  script_mandatory_keys("Pegasus/Mail/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
code or cause the application to crash by sending overly long error responses
from a remote POP3 server to the affected mail client.");
  script_tag(name:"affected", value:"Pegasus Mail 4.51 and prior.");
  script_tag(name:"insight", value:"A stack based buffer overflow error occus due to improper bounds
checking when processing POP3 responses.");
  script_tag(name:"solution", value:"Upgrade to version 4.51 or higher.");
  script_tag(name:"summary", value:"This host is running Pegasus Mail which is prone to stack-based
Buffer Overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.pmail.com/downloads_s3_t.htm");
  exit(0);
}


include("version_func.inc");

pmailVer = get_kb_item("Pegasus/Mail/Ver");
if(isnull(pmailVer)){
  exit(0);
}

if(version_is_less_equal(version:pmailVer, test_version:"4.5.1.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
