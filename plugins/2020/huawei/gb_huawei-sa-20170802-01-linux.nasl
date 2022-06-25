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
  script_oid("1.3.6.1.4.1.25623.1.0.108776");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-8890", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: 'Phoenix Talon' Vulnerabilities in Linux Kernel (huawei-sa-20170802-01-linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"The Linux operating system has four security vulnerabilities called 'Phoenix Talon', which affect Linux kernel 2.5.69 to Linux kernel 4.11.");

  script_tag(name:"insight", value:"The Linux operating system has four security vulnerabilities called 'Phoenix Talon', which affect Linux kernel 2.5.69 to Linux kernel 4.11. Successful exploit of these vulnerabilities can allow an attacker to launch DOS attacks and can lead to arbitrary code execution when certain conditions are met. (Vulnerability ID: HWPSIRT-2017-06165,HWPSIRT-2017-07130,HWPSIRT-2017-07131 and HWPSIRT-2017-07132)The four vulnerabilities have been assigned four Common Vulnerabilities and Exposures (CVE) IDs: CVE-2017-8890, CVE-2017-9075, CVE-2017-9076 and CVE-2017-9077.Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit of this vulnerability can allow an attacker to launch DOS attacks and can lead to arbitrary code execution when certain conditions are met.");

  script_tag(name:"affected", value:"AP5010DN-AGN-FAT versions V200R005C10

AP5010SN-GN versions V200R005C10 V200R006C00 V200R006C10

AP5010SN-GN-FAT versions V200R005C10

AT815SN versions V200R005C10 V200R006C00 V200R006C10

Berlin-AL10A versions Versions earlier than C00B379 Versions earlier than C00B380

Berlin-L21 versions Versions earlier than C185B362 Versions earlier than C185B362 Versions earlier than C464B135 Versions earlier than C464B135

Berlin-L21HN versions Versions earlier than C185B375 Versions earlier than C185B383 Versions earlier than C432B368 Versions earlier than C432B376

Berlin-L22 versions Versions earlier than C636B167 Versions earlier than C636B384

Berlin-L22HN versions Versions earlier than C636B372

Berlin-L23 versions Versions earlier than C605B364

Berlin-L24HN versions Versions earlier than C567B365 Versions earlier than C567B365

CAM-L21 versions Versions earlier than C636B230

CAM-L23 versions Versions earlier than C605B144CUSTC605D005

CAM-TL00H versions Versions earlier than C00B230

CAM-UL00 versions Versions earlier than C00B230

E5577B, Huawei Mobile WiFi 2 versions Versions earlier than E5577Bs-937TCPU-V200R001B327D01SP00C00

E5673s-609 versions Versions earlier than TCPU-V200R001B327D01SP00C00 Versions earlier than TCPU-V200R001B329D03SP00C00

EVA-AL10 versions Versions earlier than C00B392

EVA-L09 versions Versions earlier than C185B396 Versions earlier than C432B391 Versions earlier than C464B384 Versions earlier than C576B386 Versions earlier than C605B390 Versions earlier than C635B387 Versions earlier than C636B388

EVA-L19 versions Versions earlier than C185B393 Versions earlier than C432B388 Versions earlier than C432B388 Versions earlier than C605B390 Versions earlier than C636B391

EVA-L29 versions Versions earlier than C636B389 Versions earlier than C636B393

FRD-AL00 versions Versions earlier than C00B391 Versions earlier than C00B391

FRD-DL00 versions Versions earlier than C00B391

FRD-L02 versions Versions earlier than C432B394 Versions earlier than C635B388

FRD-L04 versions Versions earlier than C567B388 Versions earlier than C605B131CUSTC605D004

FRD-L09 versions Versions earlier than C185B387 Versions earlier than C185B387 Versions earlier than C432B140 Versions earlier than C432B394 Versions earlier than C636B387

FRD-L14 versions Versions earlier than C567B388

FRD-L19 versions Versions earlier than C432B140 Versions earlier than C432B398 Versions earlier than C636B387

FusionCompute versions V100R006C00 V100R006C10SPC100

FusionSphere OpenStack versions V100R006C00RC1B055 V100R006C00RC3B036

HiSTBAndroid versions V600R001C00SPC061

KNT-AL20 versions Versions earlier than C00B391

KNT-UL10 versions Versions earlier than C00B391

LON-AL00B versions Versions earlier than C00B231

ME909s-821 versions Versions earlier than TCPU-V100R001B617D05SP00C00

MHA-L09B versions Versions earlier than C185B181 Versions earlier than C432B197 Versions earlier than C605B116CUSTC605D116

Mobile WiFi2(Cat6) versions Versions earlier than E5785Lh-22cTCPU-V200R001B170D61SP00C00

NEM-AL10 versions Versions earlier than C00B202

NEM-L21 versions Versions earlier than C432B352

NEM-L22 versions Versions earlier than C636B357

NEM-L51 versions Versions earlier than C432B357 Versions earlier than C432B357

NEM-TL00H versions Versions earlier than C00B203

NEM-UL10 versions Versions earlier than C00B203

NMO-L22 versions Versions earlier than C569B150 Versions earlier than C569B160

NMO-L23 versions Versions earlier than C605B356 Versions earlier than C605B359 Versions earlier than C605B359

NMO-L31 versions Versions earlier than C185B357 Versions earlier than C185B359 Versions earlier than C432B357 Versions earlier than C432B358 Versions earlier than C464B356 Versions earlier than C464B357

NXT-L09A versions Versions earlier than C576B197

Prague-AL00A versions Versions earlier than C00B190 Versions earlier than C00B202

Prague-AL00B versions Versions earlier than C00B190 Versions earlier than C00B202

Prague-AL00C versions Versions earlier than C00B190 Versions earlier than C00B202

Prague-L31 versions Versions earlier than C576B161

Secospace USG6600 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50

Stanford-AL00 versions Versions earlier than C00B155

Stanford-L09 versions Versions earlier than C432B130

UMA versions V300R001C00

VIE-L09 versions Versions earlier than C02B342 Versions earlier than C109B344 Versions earlier than C113B372 Versions earlier than C150B374 Versions earlier than C25B324CUSTC25D001 Versions earlier than C318B182 Versions earlier than C40B351 Versions earlier than C432B377 Versions earlier than C55B384 Versions earlier than C576B332 Versions earlier than C605B371 Versions earlier than C605B371 Versions earlier than C706B383 Versions earlier than ITAC555B372

VIE-L29 versions Versions earlier than C185B385 Versions earlier than C605B378 Versions earlier than C605B378 Versions earlier than C636B386

VNS-AL00 versions Versions earlier than C00B243

VNS-L21 versions Versions earlier than C185B385 Versions earlier than C185B386 Versions earlier than C432B382 Versions earlier than C432B389

VNS-L22 versions Versions earlier than C185B151 Versions earlier than C185B382 Versions earlier than C569B152 Versions earlier than C576B382 Versions earlier than C576B382 Versions earlier than C635B386 Versions earlier than C636B384

VNS-L23 versions Versions earlier than C605B372 Versions earlier than C605B372

VNS-L31 versions Versions earlier than C636B391

VNS-L53 versions Versions earlier than C605B120CUSTC605D101

Warsaw-AL00 versions Versions earlier than C00B19X Versions earlier than C00B200

Warsaw-L01 versions Versions earlier than C185B17X Versions earlier than C432B17X

Warsaw-L03 versions Versions earlier than C605B17X

Warsaw-L03T versions Versions earlier than C605B17X

Warsaw-L21 versions Versions earlier than C185B17X Versions earlier than C432B17X Versions earlier than C576B17X

Warsaw-L22J versions Versions earlier than C635B172 Versions earlier than C635B17X

Warsaw-L23 versions Versions earlier than C605B172 Versions earlier than C605B17X");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170802-01-linux-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
