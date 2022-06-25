###############################################################################
# OpenVAS Vulnerability Test
#
# Flaw in Certificate Enrollment Control (Q323172)
#
# Authors:
# Michael Scheidell SECNAP Network Security
#
# Copyright:
# Copyright (C) 2002 SECNAP Network Security, LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11144");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2002-0699");
  script_name("Flaw in Certificate Enrollment Control (Q323172)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 SECNAP Network Security, LLC");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"A vulnerability in the Certificate Enrollment
  ActiveX Control in Microsoft Windows 98, Windows 98 Second Edition, Windows Millennium,
  Windows NT 4.0, Windows 2000, and Windows XP allows remote attackers to delete digital
  certificates on a user's system via HTML.");

  script_tag(name:"impact", value:"Denial of service.");

  script_tag(name:"affected", value:"Microsoft Windows 98

  Microsoft Windows 98 Second Edition

  Microsoft Windows Millennium

  Microsoft Windows NT 4.0

  Microsoft Windows 2000

  Microsoft Windows XP");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms02-048.mspx");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(nt:7, win2k:4, xp:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q323172") > 0 )
  security_message(port:0);
