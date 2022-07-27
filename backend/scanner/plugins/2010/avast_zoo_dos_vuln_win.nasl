##############################################################################
# OpenVAS Vulnerability Test
# $Id: avast_zoo_dos_vuln_win.nasl 11546 2018-09-22 11:30:16Z cfischer $
#
# Avast! Zoo Denial of Service Vulnerability
#
# LSS-NVT-2010-039
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
  script_oid("1.3.6.1.4.1.25623.1.0.102050");
  script_version("$Revision: 11546 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 13:30:16 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)");
  script_cve_id("CVE-2007-1672");
  script_bugtraq_id(23823);
  script_name("Avast! Zoo Denial of Service Vulnerability");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Denial of Service");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_mandatory_keys("Avast!/AV/Win/Ver");

  script_tag(name:"solution", value:"Update to a newer version.");

  script_tag(name:"summary", value:"avast! antivirus before 4.7.981 allows remote attackers to
  cause a denial of service (infinite loop) via a Zoo archive
  with a direntry structure that points to a previous file.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include ("version_func.inc");

version = get_kb_item("Avast!/AV/Win/Ver");
if (!version) exit (0);

if (version_is_less_equal (version: version, test_version:"4.7.981")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

exit(99);