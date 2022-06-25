# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.315154");
  script_version("2021-03-24T03:26:34+0000");
  script_cve_id("CVE-2021-26855");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-24 11:05:10 +0000 (Wed, 24 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-24 15:51:17 +0530 (Wed, 24 Mar 2021)");
  script_name("Microsoft Exchange Server 2019 ProxyLogon KB5000871 CVE-2021-26855");

  script_tag(name:"summary", value:"Microsoft Exchange Server is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Microsoft has detected multiple 0-day exploits being used
    to attack on-premises versions of Microsoft Exchange Server in limited and targeted attacks.
    In the attacks observed, the threat actor used these vulnerabilities to access on-premises
    Exchange servers which enabled access to email accounts, and allowed installation of
    additional malware to facilitate long-term access to victim environments. Microsoft Threat
    Intelligence Center (MSTIC) attributes this campaign with high confidence to HAFNIUM, a
    group assessed to be state-sponsored and operating out of China, based on observed
    victimology, tactics and procedures.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privilges.");

  script_tag(name:"affected", value:"- Microsoft Exchange Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-26855");
  script_xref(name:"URL", value:"https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/");
  script_xref(name:"URL", value:"https://msrc-blog.microsoft.com/2021/03/02/multiple-security-updates-released-for-exchange-server/");
  script_xref(name:"URL", value:"https://blogs.microsoft.com/on-the-issues/2021/03/02/new-nation-state-cyberattacks/");
  script_xref(name:"URL", value:"https://techcommunity.microsoft.com/t5/exchange-team-blog/released-march-2021-exchange-server-security-updates/ba-p/2175901");
  script_xref(name:"URL", value:"https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/");
  script_xref(name:"URL", value:"https://proxylogon.com/");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2010-service-pack-3-march-2-2021-kb5000978-894f27bf-281e-44f8-b9ba-dad705534459");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-march-2-2021-kb5000871-9800a6bb-0a21-4ee7-b9da-fa85b3e1d23b");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Mageni Security, LLC");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1, win2019:1, win2012R2:1, win8_1:1, win8_1x64:1, win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

dllVer = fetch_file_version(sysPath:sysPath, file_name:"Eventperf.dll");
if(!dllVer)
  exit(0);

if(version_is_less(version:fileVer, test_version:"15.2.659.12"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Eventperf.dll",
                            file_version:fileVer, vulnerable_range:"Less than 15.2.659.12");
  security_message(data:report);
  exit(0);
}

exit(99);
