###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pfsense_mult_vuln02_sep15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# pfSense Multiple Vulnerabilities - 02 Sep15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:pfsense:pfsense";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805971");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-6508", "CVE-2015-6509", "CVE-2015-6510", "CVE-2015-6511",
                "CVE-2015-4029");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-09-04 14:53:21 +0530 (Fri, 04 Sep 2015)");
  script_name("pfSense Multiple Vulnerabilities - 02 Sep15");

  script_tag(name:"summary", value:"This host is running pfSense and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Input passed via 'descr' parameter to system_authservers.php script,
  'proxypass' parameter to system_advanced_misc.php script, 'smtpport' parameter
  to system_advanced_notifications.php script, 'zone' parameter to
  services_captiveportal_zones.php scripts is not validated before returning to
  user.

  - Input passed via 'adaptiveend', 'adaptivestart', 'maximumstates',
  'maximumtableentries' and 'aliasesresolveinterval' parameters to
  system_advanced_firewall.php script is not validated before returning to user.

  - Input passed via the 'srctrack', 'use_mfs_tmp_size', 'use_mfs_var_size'
  parameters to system_advanced_misc.php script is not validated before returning
  to user.

  - Input passed via the 'name', 'notification_name', 'ipaddress', 'password',
  'smtpipaddress', 'smtpport', 'smtpfromaddress', 'smtpnotifyemailaddress',
  'smtpusername', and 'smtppassword' parameters to system_advanced_notifications.php
  script is not validated before returning to user.

  - Various other input validation errors. For details refer the reference section.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a user's
  browser session in the context of an affected site.");

  script_tag(name:"affected", value:"pfSense before version 2.2.3");

  script_tag(name:"solution", value:"Upgrade to version 2.2.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.pfsense.org/security/advisories/pfSense-SA-15_06.webgui.asc");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_pfsense_detect.nasl");
  script_mandatory_keys("pfsense/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!pfVer = get_app_version(cpe:CPE, nofork:TRUE)) exit(0);

if(version_is_less(version:pfVer, test_version:"2.2.3"))
{
  report = report_fixed_ver(installed_version:pfVer, fixed_version:"2.2.3");
  security_message( port:0, data:report);
  exit(0);
}

exit(99);
