##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mantis_mult_lfi_n_xss_vuln.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT Multiple Local File Include and Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902573");
  script_version("$Revision: 12818 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_bugtraq_id(49448);
  script_cve_id("CVE-2011-3356", "CVE-2011-3357", "CVE-2011-3358", "CVE-2011-3578");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("MantisBT Multiple Local File Include and Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45829/");
  script_xref(name:"URL", value:"http://www.mantisbt.org/bugs/view.php?id=13191");
  script_xref(name:"URL", value:"http://www.mantisbt.org/bugs/view.php?id=13281");
  script_xref(name:"URL", value:"https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_mantisbt.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_dependencies("mantis_detect.nasl");
  script_mandatory_keys("mantisbt/detected");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);

  script_tag(name:"insight", value:"- Input appended to the URL after manage_config_email_page.php,
    manage_config_workflow_page.php and bugs/plugin.php is not properly
    sanitised before being returned to the user.

  - Input passed to the 'action' parameter in bug_actiongroup_ext_page.php
    and bug_actiongroup_page.php is not properly verified before being used
    to include files.

  - Input passed to the 'os', 'os_build', and 'platform' parameters in
    bug_report_page.php and bug_update_advanced_page.php is not properly
    sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to MantisBT version 1.2.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is running MantisBT and is prone to multiple local file
  include and cross-site scripting vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct cross-site scripting
  attacks and disclose potentially sensitive information.");

  script_tag(name:"affected", value:"MantisBT versions prior to 1.2.8");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version:version, test_version:"1.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.8");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
