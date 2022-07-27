##############################################################################
# OpenVAS Vulnerability Test
# $Id: panda_av_bof_vuln.nasl 11548 2018-09-22 11:43:02Z cfischer $
#
# Panda Antivirus Buffer Overflow
#
# LSS-NVT-2010-041
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102052");
  script_version("$Revision: 11548 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 13:43:02 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)");
  script_cve_id("CVE-2007-3969");
  script_bugtraq_id(24989);
  script_name("Panda Antivirus Buffer Overflow");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/474247/100/0/threaded");
  script_xref(name:"URL", value:"http://secunia.com/advisories/26171");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Buffer overflow");
  script_dependencies("panda_av_update_detect.nasl");
  script_mandatory_keys("Panda/AntiVirus/LastUpdate");

  script_tag(name:"solution", value:"The vulnerability was reported on May 07 2007
  and an update has been issued on July 20 2007 to solve this vulnerability through the regular update mechanism.");

  script_tag(name:"summary", value:"Buffer overflow in Panda Antivirus before 20-07-2007
  allows remote attackers to execute arbitrary code via a crafted EXE file, resulting from an Integer Cast Around.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vuln_update = "20-07-2007";
#software not updated after this date is vulnerable

if (!last_update = get_kb_item("Panda/AntiVirus/LastUpdate")) exit(0);

#This part of code converts the dates in a format that
#is checkable using the version_func.inc constructs
last_update = ereg_replace(pattern:"^(.*)-(.*)-(.*)$", replace:"\3.\2.\1", string:last_update);
vuln_update = ereg_replace(pattern:"^(.*)-(.*)-(.*)$", replace:"\3.\2.\1",  string:vuln_update);

if(version_is_less(version: last_update, test_version:vuln_update)){
  security_message(port:0);
  exit(0);
}

exit(99);