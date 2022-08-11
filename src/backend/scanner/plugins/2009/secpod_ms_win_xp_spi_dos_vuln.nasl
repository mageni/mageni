###############################################################################
# OpenVAS Vulnerability Test
#
# Windows XP 'SPI_GETDESKWALLPAPER' DoS Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.org
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900724");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1808");
  script_bugtraq_id(35120);
  script_name("Windows XP 'SPI_GETDESKWALLPAPER' DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms09-025.mspx");
  script_xref(name:"URL", value:"http://www.ragestorm.net/blogs/?p=78");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute the malicious code
  into the context of an affected operating system and cause crash in the
  operating system.");

  script_tag(name:"affected", value:"Microsoft Windows XP SP3 and prior.");

  script_tag(name:"insight", value:"Error exists while making an 'SPI_SETDESKWALLPAPER' SystemParametersInfo
  call with an improperly terminated 'pvParam' argument, followed by an
  'SPI_GETDESKWALLPAPER' SystemParametersInfo system calls.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is running Windows XP operating system and is prone to
  Denial of Service vulnerability.

  This VT has been superseded by OID:1.3.6.1.4.1.25623.1.0.900669.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); ## This NVT is deprecated as it is superseded by KB968537 which is addressed in secpod_ms09-025.nasl