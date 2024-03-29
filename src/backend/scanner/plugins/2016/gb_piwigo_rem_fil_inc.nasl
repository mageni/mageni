##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_piwigo_rem_fil_inc.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Piwigo Remote File Inclusion Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:piwigo:piwigo';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107116");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-30 13:26:09 +0700 (Fri, 30 Dec 2016)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2016-10084", "CVE-2016-10085");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Piwigo Remote File Inclusion Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to a remote file inclusion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote file inclusion vulnerability allows remote attackers to
  include arbitrary remote files and execute PHP code on the affected computer in the context of the webserver process.");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to obtain sensitive information,
  which can lead to launching further attacks.");

  script_tag(name:"affected", value:"Piwigo prior to 2.8.5.");

  script_tag(name:"solution", value:"Update to version 2.8.5 or later.");

  script_xref(name:"URL", value:"http://piwigo.org/releases/2.8.5");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.8.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
