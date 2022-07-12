# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107832");
  script_version("2020-05-28T11:06:20+0000");
  script_tag(name:"last_modification", value:"2020-06-02 09:39:52 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2018-3639", "CVE-2018-3640");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Side-Channel Vulnerability Variants 3a and 4 (huawei-sa-20180615-01-cpu)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Intel publicly disclosed new variants of the side-channel central processing 
  unit (CPU) hardware vulnerabilities known as 'Spectre' and 'Meltdown'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Intel publicly disclosed new variants of the side-channel central processing 
  unit (CPU) hardware vulnerabilities known as 'Spectre' and 'Meltdown'.");

  script_tag(name:"impact", value:"Local attackers may exploit these vulnerabilities to cause information leak 
  on the affected system.");

  script_tag(name:"affected", value:"Huawei 1288H V5, 2288H V5, 2488 V5, 2488H V5, 5288 V3, RH1288 V3, RH2288 V3,
  RH2288H V3, XH310 V3, XH321 V3, XH620 V3, XH622 V3, XH628 V3, 5288 V5, AR3600, BH622 V2, BH640 V2, CH121 V3, 
  CH220 V3, CH222 V3, CH121 V5, CH121L V5, CH121H V3, CH121L V3, CH140L V3, CH225 V3, CH140 V3, CH226 V3, CH242 V3,
  CH242 V3 DDR4, CH242 V5, FusionCompute, Honor MagicBook (VLT-W50/ VLT-W60), HUAWEI MateBook (HZ-W09/ HZ-W19/ HZ-W29),
  HUAWEI MateBook B200/ MateBook D (PL-W09/ PL-W19/ PL-W29), HUAWEI MateBook D (MRC-W10/ MRC-W50/ MRC-W60), 
  HUAWEI MateBook X Pro (MACH-W19/ MACH-W29), ManageOne, RH1288 V2, RH1288A V2, RH2265 V2, RH2285 V2, RH2285H V2,
  RH2288 V2, RH2268 V2, RH2288A V2, RH2288E V2, RH2288H V2, RH2485 V2, RH5885 V2 4S, RH5885 V2 8S, RH5885 V3 (E7V2),
  RH5885 V3 (E7V3&E7V4), RH5885H V3 (E7V2), RH5885H V3 (E7V3), RH5885H V3 (E7V4), RH8100 V3 (E7V2&E7V3), RH8100 V3 (E7V4),
  SMC2.0 and XH321 V5.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180615-01-cpu-en");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list( "cpe:/o:huawei:ar3600_firmware" );

if( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
version = toupper( infos["version"] );

patch = get_kb_item( "huawei/vrp/patch" );

if( cpe == "cpe:/o:huawei:ar3600_firmware" ) {
  if( version == "V200R006C10" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC500" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
