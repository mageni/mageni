###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_npl_info_disc_vuln.nasl 12490 2018-11-22 13:45:33Z cfischer $
#
# Microsoft Internet Explorer Information Disclosure Vulnerability (980088)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800461");
  script_version("$Revision: 12490 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-11-22 14:45:33 +0100 (Thu, 22 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0255");
  script_bugtraq_id(38055, 38056);
  script_name("Microsoft Internet Explorer Information Disclosure Vulnerability (980088)");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/980088");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0291");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/980088.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain knowledge of
  sensitive information.");

  script_tag(name:"affected", value:"Internet Explorer Version 5.x, 6.x, 7.x, 8.x");

  script_tag(name:"insight", value:"The issue is due to the browser failing to prevent local content from
  being rendered as HTML via the 'file://' protocol, which could allow attackers
  to access files with an already known filename and location on a vulnerable
  system.");

  script_tag(name:"summary", value:"The host is installed with Internet Explorer and is prone to Information
  Disclosure vulnerability.

  This NVT has been replaced by OID:1.3.6.1.4.1.25623.1.0.902191.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms10-035.nasl