###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eureka_email_bof_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Eureka Email Stack-Based Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801041");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3837");
  script_name("Eureka Email Stack-Based Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53940");
  script_xref(name:"URL", value:"http://secunia.com/advisories/product/27632/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3025");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.org/0910-exploits/eurekamc-dos.txt");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_eureka_email_detect.nasl");
  script_mandatory_keys("EurekaEmail/Ver");
  script_tag(name:"affected", value:"Eureka Email version 2.2q and prior.");
  script_tag(name:"insight", value:"The flaw is due to a boundary error in the processing POP3 responses.
This can be exploited to cause a stack-based buffer overflow via an overly long
error response.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Eureka Email and is prone to stack-based
buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to crash an
affected client or execute arbitrary code by tricking a user into connecting to
a malicious POP3 server.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

eeVer = get_kb_item("EurekaEmail/Ver");
if(eeVer != NULL)
{
  # Eureka Email 2.2q (2.2.0.1)
  if(version_is_less_equal(version:eeVer, test_version:"2.2.0.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
