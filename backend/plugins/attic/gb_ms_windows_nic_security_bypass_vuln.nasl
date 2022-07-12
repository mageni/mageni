###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows IPv4 Default Configuration Security Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.801914");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_cve_id("CVE-2010-0232");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows IPv4 Default Configuration Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://resources.infosecinstitute.com/slaac-attack/");
  script_xref(name:"URL", value:"https://lists.immunityinc.com/pipermail/dailydave/20110404/000122.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass
  certain security restrictions and hijack all network traffic without any user.");

  script_tag(name:"affected", value:"Windows 7 Service Pack 1 and prior

  Windows Vista Service Pack 2 and prior

  Windows Server 2008 Service Pack 2 and prior");

  script_tag(name:"insight", value:"The default Network Interception Configuration prefers a new IPv6
  and DHCPv6 service over a currently used IPv4 and DHCPv4 service upon receipt of
  an IPv6 Router Advertisement (RA), and does not provide an option to ignore an
  unexpected RA, which allows remote attackers to conduct man-in-the-middle attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is installed with Microsoft Windows operating system and
  is prone to security bypass vulnerability.

  This NVT has been replaced by OID:1.3.6.1.4.1.25623.1.0.900740.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms10-015.nasl.
