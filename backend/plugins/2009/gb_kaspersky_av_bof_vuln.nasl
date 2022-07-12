###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaspersky_av_bof_vuln.nasl 14330 2019-03-19 13:59:11Z asteins $
#
# Kaspersky AntiVirus Buffer Overflow Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800242");
  script_version("$Revision: 14330 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:59:11 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-02-16 16:42:20 +0100 (Mon, 16 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(33561);
  script_cve_id("CVE-2009-0449");
  script_name("Kaspersky AntiVirus Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33788");
  script_xref(name:"URL", value:"http://www.wintercore.com/advisories/advisory_W020209.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_kaspersky_av_detect.nasl");
  script_mandatory_keys("Kaspersky/products/installed");
  script_tag(name:"affected", value:"Kaspersky AntiVirus version 7.0.1.325 and prior on Windows.
  Kaspersky AntiVirus Workstation version 6.0.3.837 and prior on Windows.");
  script_tag(name:"insight", value:"This flaw is due to an error in the klim5.sys driver when handling Kernel
  API calls IOCTL 0x80052110 which can overwrite callback function pointers
  and execute arbitrary codes into the context of the application.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Kaspersky AntiVirus or Workstation and is
  prone to Buffer Overflow Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application or may cause privilege escalation.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.kaspersky.com/productupdates?chapter=146274385");
  exit(0);
}


include("version_func.inc");

kavVer = get_kb_item("Kaspersky/AV/Ver");
if(kavVer != NULL)
{
  if(version_is_less_equal(version:kavVer, test_version:"7.0.1.325")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

kavwVer = get_kb_item("Kaspersky/AV-Workstation/Ver");
if(kavwVer != NULL)
{
  if(version_is_less_equal(version:kavwVer, test_version:"6.0.3.837")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
