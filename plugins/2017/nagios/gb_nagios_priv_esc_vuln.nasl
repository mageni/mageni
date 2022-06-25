###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_priv_esc_vuln.nasl 12038 2018-10-23 12:58:19Z asteins $
#
# Nagios Privilege Escalation Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = 'cpe:/a:nagios:nagios';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140375");
  script_version("$Revision: 12038 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 14:58:19 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-19 11:03:19 +0700 (Tue, 19 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-14312");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Nagios Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("nagios_detect.nasl");
  script_mandatory_keys("nagios/installed");

  script_tag(name:"summary", value:"Nagios is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nagios Core initially executes /usr/sbin/nagios as root but supports
  configuration options in which this file is owned by a non-root account (and similarly can have nagios.cfg owned
  by a non-root account), which allows local users to gain privileges by leveraging access to this non-root
  account.");

  script_tag(name:"affected", value:"Nagios 4.3.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://github.com/NagiosEnterprises/nagioscore/issues/424");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
