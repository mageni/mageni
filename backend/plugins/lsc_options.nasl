###############################################################################
# OpenVAS Vulnerability Test
# $Id: lsc_options.nasl 14040 2019-03-07 14:01:35Z cfischer $
#
# This script allows to set some Options for LSC.
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100509");
  script_version("$Revision: 14040 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 15:01:35 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-26 12:01:21 +0100 (Fri, 26 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Options for Local Security Checks");
  script_category(ACT_SETTINGS);
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Settings");

  # Use find command yes/no
  script_add_preference(name:"Also use 'find' command to search for Applications", type:"checkbox", value:"yes");
  # add -xdev to find yes/no
  script_add_preference(name:"Descend directories on other filesystem (don't add -xdev to find)", type:"checkbox", value:"yes");

  script_add_preference(name:"Enable Detection of Portable Apps on Windows", type:"checkbox", value:"no");

  script_add_preference(name:"Disable the usage of win_cmd_exec for remote commands on Windows", type:"checkbox", value:"no");

  script_add_preference(name:"Disable file search via WMI on Windows", type:"checkbox", value:"no");

  script_add_preference(name:"Report vulnerabilities of inactive Linux Kernel(s) separately", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This script allows users to set some Options for Local Security Checks which
  are stored in the knowledge base and used by other tests. Description of the options:

  - Also use 'find' command to search for Applications:

  Setting this option to 'no' disables the use of the 'find' command via SSH against Unixoide targets. This reduces scan
  time but might reduce detection coverage of e.g. local installed applications.

  - Descend directories on other filesystem (don't add -xdev to find):

  During the scan 'find' is used to detect e.g. local installed applications via SSH on Unixoide targets. This command is descending on
  special (network-)filesystems like NFS, SMB or similar mounted on the target host by default. Setting this option to 'no' might reduce the
  scan time if network based filesystems are not searched for installed applications.

  - Enable Detection of Portable Apps on Windows:

  Setting this option to 'yes' enables the Detection of Portable Apps on Windows via WMI. Enabling this option might increase scan time
  as well as the load on the target host.

  - Disable the usage of win_cmd_exec for remote commands on Windows:

  Some AV solutions might block remote commands called on the remote host via a scanner internal 'win_cmd_exe' function. Setting
  this option to 'yes' disables the usage of this function (as a workaround for issues during the scan) with the risk of lower
  scan coverage against Windows targets.

  - Disable file search via WMI on Windows:

  Various VTs are using WMI to search for files on Windows targets. Depending on the attached storage and its size this routine might
  put high load on the target and could slow down the scan. Setting this option to 'yes' disables the usage of this search with the
  risk of lower scan coverage against Windows targets.

  - Report vulnerabilities of inactive Linux Kernel(s) separately:

  All current package manager based Local Security Checks are reporting the same severity for active and inactive Linux Kernel(s). If this
  setting is enabled the reporting for inactive Linux Kernel(s) is done separately in the VT 'Report Vulnerabilities in inactive Linux Kernel(s)'
  (OID: 1.3.6.1.4.1.25623.1.0.108545).

  Please note that this functionality is currently only available for Debian (and Derivates using apt-get) and RPM based Distributions and needs
  to be considered as 'experimental'.");

  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

find_enabled         = script_get_preference("Also use 'find' command to search for Applications");
nfs_search_enabled   = script_get_preference("Descend directories on other filesystem (don't add -xdev to find)");
search_portable      = script_get_preference("Enable Detection of Portable Apps on Windows");
disable_win_cmd_exec = script_get_preference("Disable the usage of win_cmd_exec for remote commands on Windows");
disable_wmi_search   = script_get_preference("Disable file search via WMI on Windows");
kernel_overwrite     = script_get_preference("Report vulnerabilities of inactive Linux Kernel(s) separately");

if( find_enabled )
  set_kb_item( name:"ssh/lsc/enable_find", value:find_enabled );

if( nfs_search_enabled )
  set_kb_item( name:"ssh/lsc/descend_ofs", value:nfs_search_enabled );

if( kernel_overwrite && "yes" >< kernel_overwrite )
  set_kb_item( name:"ssh/login/kernel_reporting_overwrite/enabled", value:TRUE );

if( search_portable && "yes" >< search_portable )
  set_kb_item( name:"win/lsc/search_portable_apps", value:TRUE );

if( disable_win_cmd_exec && "yes" >< disable_win_cmd_exec )
  set_kb_item( name:"win/lsc/disable_win_cmd_exec", value:TRUE );

if( disable_wmi_search && "yes" >< disable_wmi_search )
  set_kb_item( name:"win/lsc/disable_wmi_search", value:TRUE );

exit( 0 );