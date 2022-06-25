###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows2k3 Active Directory 'BROWSER ELECTION' Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801598");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2011-02-18 17:42:11 +0100 (Fri, 18 Feb 2011)");
  script_cve_id("CVE-2011-0654");
  script_bugtraq_id(46360);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows2k3 Active Directory 'BROWSER ELECTION' Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16166");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/current/0284.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code
  with SYSTEM-level privileges or cause a denial of service condition.");

  script_tag(name:"affected", value:"Microsoft Windows 2K3 Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaw is due to an error in Active Directory in 'Mrxsmb.sys',
  which fails to perform adequate boundary-checks on user-supplied data in crafted BROWSER ELECTION request.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with Active Directory and is prone to buffer
  overflow vulnerability.

  This NVT has been replaced by OID:1.3.6.1.4.1.25623.1.0.900279.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms11-019.nasl.
