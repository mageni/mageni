###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_sharepoint_xss_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Microsoft SharePoint Cross Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800481");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_cve_id("CVE-2010-0716");
  script_name("Microsoft SharePoint Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://www.hacktics.com/content/advisories/AdvMS20100222.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/509683/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("remote-detect-WindowsSharepointServices.nasl");
  script_mandatory_keys("MicrosoftSharePointTeamServices/version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to leverage
same-origin relationships and conduct cross-site scripting attacks by
uploading TXT files.");
  script_tag(name:"affected", value:"Microsoft Office SharePoint Server 2007 12.0.0.6421 and prior.");
  script_tag(name:"insight", value:"This flaw is due to insufficient validation of user supplied data
  passed into 'SourceUrl' and 'Source' parameters in the 'download.aspx' in
  SharePoint Team Services.");
  script_tag(name:"solution", value:"Upgrade to SharePoint Server 2010 or later.");
  script_tag(name:"summary", value:"This host is running Microsoft SharePoint Server and is prone to
  Cross Site Scripting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://sharepoint.microsoft.com/Pages/Default.aspx");
  exit(0);
}


include("version_func.inc");

stsVer = get_kb_item("MicrosoftSharePointTeamServices/version");
if(isnull(stsVer)){
  exit(0);
}

if(version_in_range(version:stsVer, test_version:"12.0", test_version2:"12.0.0.6421")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
