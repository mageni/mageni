##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_vse_untrusted_searchpath_vuln_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# McAfee VirusScan Enterprise Untrusted Search Path Vulnerability (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803322");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2009-5118");
  script_bugtraq_id(45080);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-02-21 19:41:20 +0530 (Thu, 21 Feb 2013)");
  script_name("McAfee VirusScan Enterprise Untrusted Search Path Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2009-5118");
  script_xref(name:"URL", value:"http://www.naked-security.com/cve/CVE-2009-5118");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mcafee_virusscan_enterprise_detect_win.nasl");
  script_mandatory_keys("McAfee/VirusScan/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
code via a crafted document embedded with ActiveX control.");
  script_tag(name:"affected", value:"McAfee VirusScan Enterprise versions prior to 8.7i");
  script_tag(name:"insight", value:"Flaw is due to loading dynamic-link libraries (DLL) from an
untrusted path.");
  script_tag(name:"solution", value:"Apply HF669863 patch for version 8.5i or
Upgrade to version 8.7i or later.");
  script_tag(name:"summary", value:"This host is installed with McAfee VirusScan Enterprise and is
prone to untrusted search path vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mcafee.com");
  exit(0);
}

include("version_func.inc");

version = get_kb_item("McAfee/VirusScan/Win/Ver");
if(version)
{
  if(version_is_less(version:version, test_version:"8.7i"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
