###############################################################################
# OpenVAS Vulnerability Test
# $Id: spysweeper_corp_installed.nasl 11964 2018-10-18 12:44:10Z cfischer $
#
# Webroot SpySweeper Enterprise Check
#
# Authors:
# Montgomery County
# Original script was written by Jeff Adams <jeffadams@comcast.net>
# and Tenable Network Security
#
# Copyright:
# Copyright (C) 2004-2005 Jeff Adams / Tenable Network Security
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
  script_oid("1.3.6.1.4.1.25623.1.0.80046");
  script_version("$Revision: 11964 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 14:44:10 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Webroot SpySweeper Enterprise Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004-2005 Jeff Adams / Tenable Network Security");
  script_family("Product detection");
  script_dependencies("smb_enum_services.nasl", "smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"This plugin checks that the remote host has
  Webroot Spy Sweeper Enterprise installed and properly running, and makes sure
  that the latest Vdefs are loaded.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#


#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#
function check_signature_version ()
{
  local_var key, item, key_h, value, path, vers;

  key = "SOFTWARE\Webroot\Enterprise\CommAgent\";
  item = "sdfv";

  if(!registry_key_exists(key:key)){
    return NULL;
  }

  value = registry_get_sz(item:item, key:key);
  if(value) {
    set_kb_item(name: "Antivirus/SpySweeperEnt/signature", value:value);
    return value;
  } else {
    return NULL;
  }
}


#-------------------------------------------------------------#
# Checks the product version                                  #
# Ugh -- the only way to determine product version is to look #
# within SpySweeper.exe.                                      #
#-------------------------------------------------------------#
function check_product_version ()
{
  local_var key, item, key_h, value;

  key = "SOFTWARE\Webroot\Enterprise\Spy Sweeper\";
  if (registry_key_exists(key:key)) {
      value = registry_get_sz(item:"id", key:key);
      if (value) path = value;
      else path = NULL;
  }
  else path = NULL;
  if (isnull(path)) {
    exit(0);
  }

  file = path + "\SpySweeperUI.exe";
  version = GetVersionFromFile(file:file);
  if (isnull(version))
  {
    ver = "Unable to determine version";
    set_kb_item(name: "Antivirus/SpySweeperEnt/version", value:ver);

    register_and_report_cpe(app:"Spy Sweeper Ent", ver:ver, base:"cpe:/a:webroot_software:spy_sweeper_enterprise:",
                            expr:"^([0-9.]+)");
    exit(0);
  }
   ver = string(version);
   set_kb_item(name: "Antivirus/SpySweeperEnt/version", value:ver);

   register_and_report_cpe(app:"Spy Sweeper Ent", ver:ver, base:"cpe:/a:webroot_software:spy_sweeper_enterprise:",
                            expr:"^([0-9.]+)");
   return ver;
}

#==================================================================#
# Section 2. Main code                                             #
#==================================================================#

#-------------------------------------------------------------#
# Checks if Spy Sweeper Enterprise is installed               #
#-------------------------------------------------------------#

value = NULL;

key = "SOFTWARE\Webroot\Enterprise\Spy Sweeper\";
item = "id";

if (registry_key_exists(key:key))
{
 value = registry_get_sz(item:item, key:key);
}

if (!value)
{
  exit(0);
}

set_kb_item(name: "Antivirus/SpySweeperEnt/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks if Spy Sweeper Enterprise has Parent server set      #
#-------------------------------------------------------------#

value = NULL;

key = "SOFTWARE\Webroot\Enterprise\CommAgent\";
item = "su";

if (registry_key_exists(key:key))
{
 value = registry_get_sz(item:item, key:key);
}

if ( strlen (value) <=1 )
{
  set_kb_item(name: "Antivirus/SpySweeperEnt/noparent", value:TRUE);
}
else
{
  set_kb_item(name: "Antivirus/SpySweeperEnt/parent", value:value);
}

#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#
current_signature_version = check_signature_version ();

#-------------------------------------------------------------#
# Checks if Spy Sweeper is running                            #
# Both of these need to running in order to ensure proper     #
# operation.                                                  #
#-------------------------------------------------------------#

services = get_kb_item("SMB/svcs");

if ( services )
{
  if (("WebrootSpySweeperService" >!< services) || ("Webroot CommAgent Service" >!< services))
    running = 0;
  else
    running = 1;
}

#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
product_version = check_product_version ();
if(!product_version && !current_signature_version)exit(0);

#==================================================================#
# Section 4. Final Report                                          #
#==================================================================#

# var initialization
warning = 0;

#
# We first report information about the antivirus
#
report = "
The remote host has the Webroot Spy Sweeper Enterprise installed. It has
been fingerprinted as :

";

report += "Spy Sweeper Enterprise " + product_version + "
DAT version : " + current_signature_version + "

";

#
# Check if antivirus signature is up-to-date
#

# Last Database Version
# Updates are located here:
# http://www.webroot.com/entcenter/index.php
virus = "";
if(current_signature_version && current_signature_version>0) {
  if ( int(current_signature_version) < int(virus) )
  {
    report += "The remote host has an out-dated version of the Spy
Sweeper virus signatures. Last version is " + virus + "

  ";
    warning = 1;
  }
}

#
# Check if antivirus is running
#

if (services && !running)
{
  report += "The remote Spy Sweeper Enterprise is not running.

";
  set_kb_item(name: "Antivirus/SpySweeperEnt/running", value:FALSE);
  warning = 1;
}
else
{
  set_kb_item(name: "Antivirus/SpySweeperEnt/running", value:TRUE);
}

#
# Create the final report
#

if (warning)
{
  report += "As a result, the remote host might be infected by spyware
received by browsing or other means.";

  log_message(port:0, data:report);
}
else
{
  set_kb_item (name:"Antivirus/SpySweeperEnt/description", value:report);
}
