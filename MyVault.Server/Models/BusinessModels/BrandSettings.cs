using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MyVault.Server.Services;

namespace MyVault.Server.Models.BusinessModels
{
    /// <summary>
    /// Brand settings model
    /// </summary>
    public class BrandSettings : AppSettingsBase
    {
        /// <summary>
        /// property ApplicationName
        /// </summary>
        /// <value>string</value>
        public string? ApplicationName { get; set; }
        /// <summary>
        /// primary color property
        /// </summary>
        /// <value></value>
        public string? ColorPrimary { get; set; }
        /// <summary>
        /// secondary color property
        /// </summary>
        /// <value></value>
        public string? ColorSecondary { get; set; }
        /// <summary>
        /// Info color property
        /// </summary>
        /// <value></value>
        public string? ColorInfo { get; set; }
        /// <summary>
        /// Success color property
        /// </summary>
        /// <value></value>
        public string? ColorSuccess { get; set; }
        /// <summary>
        /// Warning color property
        /// </summary>
        /// <value></value>
        public string? ColorWarning { get; set; }
        /// <summary>
        /// Danger color property
        /// </summary>
        /// <value></value>
        public string? ColorDanger { get; set; }
        /// <summary>
        /// light Background color property
        /// </summary>
        /// <value></value>
        public string? ColorLightBackground { get; set; }
        /// <summary>
        /// property to sdtore the application Logo
        /// </summary>
        /// <value></value>
        public string? ApplicationLogo { get; set; }
        /// <summary>
        /// headline color property
        /// </summary>
        /// <value></value>
        public string? ColorHeadlines { get; set; }
        /// <summary>
        /// link color property
        /// </summary>
        /// <value></value>
        public string? ColorLink { get; set; }
        /// <summary>
        /// muted text color property
        /// </summary>
        /// <value></value>
        public string? ColorTextMuted { get; set; }
        /// <summary>
        /// AuthLayoutBgImage property
        /// </summary>
        /// <value></value>
        public string? LoginBackground { get; set; }
        /// <summary>
        /// SideBarBackground property
        /// </summary>
        /// <value></value>
        public string? SideBarBackground {get;set;}
        /// <summary>
        /// HeadBarBackground property
        /// </summary>
        /// <value></value>
        public string? HeadBarBackground {get;set;}
        /// <summary>
        /// HeadBarTextColor property
        /// </summary>
        /// <value></value>
        public string? HeadBarTextColor {get;set;}
        /// <summary>
        /// set carbon style
        /// </summary>
        /// <value></value>
        public bool EnableCarbonStyle {get;set;} = true;
    }
}