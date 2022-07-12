##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rabbitmq_dos_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# RabbitMQ DoS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/a:pivotal_software:rabbitmq';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106499");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-06 12:45:06 +0700 (Fri, 06 Jan 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2015-8786");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RabbitMQ DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_rabbitmq_amqp_detect.nasl");
  script_mandatory_keys("rabbitmq/amqp/installed");

  script_tag(name:"summary", value:"RabbitMQ is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"RabbitMQ allows remote authenticated users with certain
privileges to cause a denial of service (resource consumption) via the 'lengths_age' or 'lengths_incr'
parameter.");

  script_tag(name:"impact", value:"An authenticated attacker may cause a denial of service condition.");

  script_tag(name:"affected", value:"RabbitMQ before 3.6.1.");

  script_tag(name:"solution", value:"Update to version 3.6.1");

  script_xref(name:"URL", value:"https://github.com/rabbitmq/rabbitmq-server/releases/tag/rabbitmq_v3_6_1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less(version: version, test_version: "3.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
