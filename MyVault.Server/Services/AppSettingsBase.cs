using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using MyVault.Server.Data;
using MyVault.Shared.Models.DataModels;

namespace MyVault.Server.Services
{
    /// <summary>
    /// base class for Settings classes
    /// </summary>
    public abstract class AppSettingsBase
    {

        /// <summary>
        /// name property
        /// </summary>
        private readonly string _name;
        /// <summary>
        /// propertyinfo array
        /// </summary>
        private readonly PropertyInfo[] _properties;

        /// <summary>
        /// class constructor
        /// </summary>
        public AppSettingsBase()
        {
            var type = this.GetType();
            _name = type.Name;
            // 2
            _properties = type.GetProperties();
        }

        /// <summary>
        /// load method
        /// </summary>
        /// <param name="unitOfWork">type DbContext</param>
        public virtual void Load(AppDbContext unitOfWork)
        {
            // ARGUMENT CHECKING SKIPPED FOR BREVITY
            // 3 get settings for this type name

            var settings = unitOfWork.AppSettings!.Where(w => w.Type == _name).ToList();

            foreach (var propertyInfo in _properties)
            {
                // get the setting from the settings list
                var setting = settings.SingleOrDefault(s => s.Name == propertyInfo.Name);
                if (setting != null)
                {
                    // 4 assign the setting values to the properties in the type inheriting this class
                    propertyInfo.SetValue(this, Convert.ChangeType(setting.Value, propertyInfo.PropertyType));
                }
            }
        }

        /// <summary>
        /// save method
        /// </summary>
        /// <param name="unitOfWork">type DbContext</param>
        public virtual async Task Save(AppDbContext unitOfWork)
        {
            // 5 load existing settings for this type
            var settings = unitOfWork.AppSettings!.Where(w => w.Type == _name).ToList();

            foreach (var propertyInfo in _properties)
            {
                object propertyValue = propertyInfo.GetValue(this, null)!;
                string value = (propertyValue == null) ? null! : propertyValue.ToString()!;

                var setting = settings.SingleOrDefault(s => s.Name == propertyInfo.Name);
                if (setting != null)
                {
                    // 6 update existing value
                    setting.Value = value;
                    unitOfWork.SaveChanges();
                }
                else
                {
                    // 7 create new setting
                    var newSetting = new ApplicationSettings()
                    {
                        Name = propertyInfo.Name,
                        Type = _name,
                        Value = value,
                    };
                    await unitOfWork.AppSettings!.AddAsync(newSetting);
                }
            }
        }
    }
}