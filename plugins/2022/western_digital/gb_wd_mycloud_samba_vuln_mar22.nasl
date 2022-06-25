# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113857");
  script_version("2022-03-25T10:45:53+0000");
  script_tag(name:"last_modification", value:"2022-03-25 11:41:51 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-24 06:15:29 +0000 (Thu, 24 Mar 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-23 15:47:00 +0000 (Wed, 23 Feb 2022)");

  script_cve_id("CVE-2021-44142");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.0 < 5.21.104 Samba Vulnerability (WDC-22006)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to a
  vulnerability in Samba.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Samba is vulnerable to an out-of-bounds heap read write
  vulnerability that allows remote attackers to execute arbitrary code as root on affected Samba
  installations that use the VFS module vfs_fruit.

  The specific flaw exists within the parsing of EA metadata when opening files in smbd. Access as
  a user that has write access to a file's extended attributes is required to exploit this
  vulnerability. Note that this could be a guest or unauthenticated user if such users are allowed
  write access to file extended attributes.

  The problem in vfs_fruit exists in the default configuration of the fruit VFS module using
  fruit:metadata=netatalk or fruit:resource=file. If both options are set to different settings
  than the default values, the system is not affected by the security issue.");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100, My Cloud
  EX4100, My Cloud EX2 Ultra, My Cloud Mirror Gen 2, My Cloud DL2100, My Cloud DL4100, My Cloud
  EX2100, My Cloud and WD Cloud with firmware versions prior to 5.21.104.");

  script_tag(name:"solution", value:"Update to firmware version 5.21.104 or later.");

  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-22006-my-cloud-os5-firmware-5-21-104");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2021-44142.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:wd_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
                     "cpe:/o:wdc:my_cloud_ex2100_firmware",
                     "cpe:/o:wdc:my_cloud_ex4100_firmware",
                     "cpe:/o:wdc:my_cloud_dl2100_firmware",
                     "cpe:/o:wdc:my_cloud_dl4100_firmware",
                     "cpe:/o:wdc:my_cloud_pr2100_firmware",
                     "cpe:/o:wdc:my_cloud_pr4100_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.21.104")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.21.104");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
