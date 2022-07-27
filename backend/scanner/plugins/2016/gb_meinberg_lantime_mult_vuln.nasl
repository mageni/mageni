###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_meinberg_lantime_mult_vuln.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Meinberg LANTIME Multiple Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106110");
  script_version("$Revision: 12363 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-24 16:45:17 +0700 (Fri, 24 Jun 2016)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");

  script_cve_id("CVE-2016-3962", "CVE-2016-3988", "CVE-2016-3989");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Meinberg LANTIME Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_meinberg_lantime_detect.nasl");
  script_mandatory_keys("meinberg_lantime/detected");

  script_tag(name:"summary", value:"Meinberg LANTIME is prone to multiple vulnerabilies");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Meinberg LANTIME is prone to multiple vulnerabilies:

Remote stack buffer overflow vulnerability involving parsing of parameter in POST request in function
provides privilege of web server 'nobody'. (CVE-2016-3962)

Remote stack buffer overflow vulnerability is present while parsing nine different parameters in POST
request in function. (CVE-2016-3988)

Weak access controls allow for privilege escalation from 'nobody' to 'root' user. 'nobody' has permissions
to alter script that can only run as 'root'. (CVE-2016-3989)");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities could cause a buffer
overflow condition that may allow escalation to root privileges.");

  script_tag(name:"affected", value:"Version prior to 6.20.004 on IMS-LANTIME M3000, IMS-LANTIME M1000,
IMS-LANTIME M500, LANTIME M900, LANTIME M600, LANTIME M400, LANTIME M300, LANTIME M200 and LANTIME M100.");

  script_tag(name:"solution", value:"Upgrade to Version 6.20.004 or later");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-175-03");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:meinberg:lantime_m3000",
                      "cpe:/a:meinberg:lantime_m1000",
                      "cpe:/a:meinberg:lantime_m500",
                      "cpe:/a:meinberg:lantime_m900",
                      "cpe:/a:meinberg:lantime_m600",
                      "cpe:/a:meinberg:lantime_m400",
                      "cpe:/a:meinberg:lantime_m300",
                      "cpe:/a:meinberg:lantime_m200",
                      "cpe:/a:meinberg:lantime_m100" );

if( ! version = get_app_version( cpe:cpe_list ) ) exit( 0 );

if( version_is_less( version:version, test_version:"6.20.004" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.20.004" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
