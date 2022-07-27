###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_freesshd_pre_auth_dos_vuln.nasl 13562 2019-02-11 07:35:15Z cfischer $
#
# freeSSHd Pre-Authentication Error Remote DoS Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900960");
  script_version("$Revision: 13562 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 08:35:15 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-01 12:15:29 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3340");
  script_bugtraq_id(36235);
  script_name("freeSSHd Pre-Authentication Error Remote DoS Vulnerability");
  script_xref(name:"URL", value:"http://intevydis.com/vd-list.shtml");
  script_xref(name:"URL", value:"http://www.intevydis.com/blog/?p=57");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36506");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Sep/1022811.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_freesshd_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("freeSSHd/Ver");

  script_tag(name:"impact", value:"Successful attack could allow attackers to crash application to cause
  denial of service.");

  script_tag(name:"affected", value:"freeSSHd version 1.2.4 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified pre-authentication error.");

  script_tag(name:"solution", value:"Upgrade to freeSSHd version 1.2.6 or later.");

  script_tag(name:"summary", value:"This host has freeSSHd installed and is prone to Denial of Service
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.freesshd.com/");

  exit(0);
}

include("version_func.inc");

sshdVer = get_kb_item("freeSSHd/Ver");
if(sshdVer)
{
  if(version_is_less_equal(version:sshdVer, test_version:"1.2.4")){
    security_message(port:0);
  }
}