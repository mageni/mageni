###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trane_tracer_sc_info_discl_vuln.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Trane Tracer SC Information Exposure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/a:trane:tracer_sc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106273");
  script_version("$Revision: 12313 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-20 17:00:53 +0700 (Tue, 20 Sep 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-0870");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Trane Tracer SC Information Exposure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_trane_tracer_sc_detect.nasl");
  script_mandatory_keys("trane_tracer/detected");

  script_tag(name:"summary", value:"Trane Tracer SC is prone to a information exposure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability allows an unauthorized party to obtain sensitive
information from the contents of configuration files not protected by the web server.");

  script_tag(name:"impact", value:"An unauthorized attacker can exploit these vulnerability to read sensitive
information from the contents of configuration files.");

  script_tag(name:"affected", value:"Versions 4.2.1134 and below.");

  script_tag(name:"solution", value:"Contact the vendor for an update.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-259-03");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.2.1134")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Contact vendor");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
