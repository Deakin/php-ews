<?php
/**
 * Definition of the GetUserConfigurationType type
 *
 * @package php-ews
 * @subpackage Types
 */

namespace PhpEws\EWSType;

use PhpEws\EWSType\EWSType;

/**
 * Definition of the GetUserConfigurationType type
 */
class GetUserConfigurationType extends EWSType
{
    /**
     * UserConfigurationName property
     *
     * @var PhpEws\EWSType\UserConfigurationNameType
     */
    public $UserConfigurationName;

    /**
     * UserConfigurationProperties property
     *
     * @var UserConfigurationPropertyType
     */
    public $UserConfigurationProperties;

}
