###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bigtree_cve_2016_10223.nasl 11962 2018-10-18 10:51:32Z mmartin $
#
# Bigtree CMS Potential XSS Attack
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:bigtree:bigtree";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140164");
  script_version("$Revision: 11962 $");
  script_cve_id("CVE-2016-10223");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:51:32 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-17 10:34:05 +0100 (Fri, 17 Feb 2017)");
  script_name("Bigtree CMS Potential XSS Attack");

  script_tag(name:"summary", value:"An issue was discovered in BigTree CMS before 4.2.15. The vulnerability exists due to insufficient filtration of user-supplied data in the `id` HTTP GET parameter passed to the `core/admin/adjax/dashboard/check-module-integrity.php` URL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to, - An improper validation of input to 'cleanFile' Function.");

  script_tag(name:"impact", value:"An attacker could execute arbitrary HTML and script code in a browser in the context of the vulnerable website.");

  script_tag(name:"affected", value:"BigTree before 4.2.15");

  script_tag(name:"solution", value:"Upgrade to version 4.2.15 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_bigtree_detect.nasl");
  script_mandatory_keys("BigTree/Installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.bigtreecms.org/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!bigtreePort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!bigtreeVer = get_app_version(port:bigtreePort, cpe:CPE)){
  exit(0);
}

if(version_is_less(version:bigtreeVer, test_version:"4.2.15"))
{
  report = report_fixed_ver(installed_version:bigtreeVer, fixed_version:"4.2.15");
  security_message(data:report, port:bigtreePort);
  exit(0);
}

exit( 99 );
