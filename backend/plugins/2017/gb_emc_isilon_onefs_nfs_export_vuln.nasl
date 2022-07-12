##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_isilon_onefs_nfs_export_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# EMC Isilon OneFS NFS Export Upgrade Vulnerability
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

CPE = "cpe:/o:emc:isilon_onefs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106805");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-16 16:14:35 +0700 (Tue, 16 May 2017)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2017-4979");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EMC Isilon OneFS NFS Export Upgrade Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_emc_isilon_onefs_snmp_detect.nasl", "gb_emc_isilon_onefs_ftp_detect.nasl",
"gb_emc_isilon_onefs_ntp_detect.nasl");
  script_mandatory_keys("emc_isilon_onefs/detected");

  script_tag(name:"summary", value:"EMC Isilon OneFS is affected by an NFS export vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"EMC Isilon OneFS is affected by the OneFS NFS Export Upgrade Vulnerability.
Changing the default export permissions, after having created exports and then upgrading OneFS, can result in
giving access to users that shouldn't have it, or in prohibiting access to those that should have access.");

  script_tag(name:"affected", value:"EMC Isilon OneFS 7.2.0.x, 7.2.1.0 - 7.2.1.3, 8.0.0.0 - 8.0.0.2 and
8.0.1.0.");

  script_tag(name:"solution", value:"Update to 7.2.1.4, 8.0.0.3, 8.0.1.1 or later versions.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2017/May/att-28/ESA-2017-027.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "7.2.0.0"))
  exit(99);

if (version_is_less(version: version, test_version: "7.2.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1.4");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0.0", test_version2: "8.0.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.3");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "8.0.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.1.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
