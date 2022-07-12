# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143198");
  script_version("2019-12-06T01:36:56+0000");
  script_tag(name:"last_modification", value:"2019-12-06 01:36:56 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-11-28 07:34:54 +0000 (Thu, 28 Nov 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Digitalisierungsbox < 11.1.2.102 Port Forwarding Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_digitalisierungsbox_consolidation.nasl");
  script_mandatory_keys("digitalisierungsbox/detected");

  script_tag(name:"summary", value:"Digitalisierungsbox Premium, Smart and Standard are prone to a faulty
  port-forwarding vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"The device is forwarding too many ports in case HTTP or HTTPS is used in the
  port forwarding settings. For HTTP the port range 80-89 is forwarded and in case of HTTPS the port range 440-449.");

  script_tag(name:"impact", value:"If services on the mentioned port ranges are open in the local network (e.g.
  SMB (port 445/tcp)) an attacker might access those over the internet.");

  script_tag(name:"affected", value:"Digitalisierungsbox Premium, Smart and Standard with firmware prior to 11.1.2.102.");

  script_tag(name:"solution", value:"Update to firmware version 11.1.2.102 or later.");

  script_xref(name:"URL", value:"https://www.heise.de/ct/artikel/Warum-eine-komplette-Arztpraxis-offen-im-Netz-stand-4590103.html");
  script_xref(name:"URL", value:"https://www.heise.de/security/meldung/Nach-Datenleck-in-Arztpraxis-Weitere-Router-betroffen-jetzt-patchen-4596678.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:telekom:digitalisierungsbox_premium_firmware",
                     "cpe:/o:telekom:digitalisierungsbox_smart_firmware",
                     "cpe:/o:telekom:digitalisierungsbox_standard_firmware");


if (!version = get_app_version(cpe: cpe_list, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "11.1.2.102")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.1.2.102");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
