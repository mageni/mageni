###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Color Control Panel Privilege Escalation Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802383");
  script_version("2019-05-03T12:31:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2010-5082");
  script_bugtraq_id(44157);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-01-19 16:17:52 +0530 (Thu, 19 Jan 2012)");
  script_name("Microsoft Windows Color Control Panel Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"http://www.koszyk.org/b/archives/82");
  script_xref(name:"URL", value:"http://shinnai.altervista.org/exploits/SH-006-20100914.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Windows");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful attempt could allow local attackers to bypass security
  restrictions and gain the privileges.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 SP2");

  script_tag(name:"insight", value:"The flaw is due to an error in the Color Control Panel, which
  allows attackers to gain privileges via a Trojan horse sti.dll file in the current working directory.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"Microsoft Windows Server 2008 SP2 is prone to privilege
  escalation vulnerability.

  This NVT has been replaced by OID:1.3.6.1.4.1.25623.1.0.902791.");

  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-012");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms12-012.nasl