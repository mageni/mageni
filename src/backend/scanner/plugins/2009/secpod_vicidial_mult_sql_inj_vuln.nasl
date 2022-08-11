###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vicidial_mult_sql_inj_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# VICIDIAL Call Center Suite Multiple SQL Injection Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:vicidial:vicidial";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900916");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2234");
  script_bugtraq_id(35056);
  script_name("VICIDIAL Call Center Suite Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8755");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50665");
  script_xref(name:"URL", value:"http://www.eflo.net/VICIDIALforum/viewtopic.php?t=8075");
  script_xref(name:"URL", value:"http://www.eflo.net/vicidial/security_fix_admin_20090522.patch");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_vicidial_detect.nasl");
  script_mandatory_keys("vicidial/installed");

  script_tag(name:"impact", value:"Attackers can exploit this issue via specially crafted SQL statements to
  access and modify the back-end database.");

  script_tag(name:"affected", value:"VICIDIAL Call Center Suite 2.0.5 through 2.0.5-173");

  script_tag(name:"insight", value:"This flaw occurs due to lack of sanitation of user supplied data passed into
  the admin.php and can be exploited via username and password parameters.");

  script_tag(name:"summary", value:"This host is installed with VICIDIAL Call Center Suite and is
  prone to multiple SQL Injection vulnerabilities.");

  script_tag(name:"solution", value:"Apply the available patch linked at the references.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

version = ereg_replace(pattern: "-", replace: ".", string: version);

if (version_is_less_equal(version: version, test_version: "2.0.5.206")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply patch");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);