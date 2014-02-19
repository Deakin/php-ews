<?php
/**
 * Definition of the UserConfigurationDictionaryObjectType type
 *
 * @package php-ews
 * @subpackage Types
 */

namespace PhpEws\EWSType;

use PhpEws\EWSType\EWSType;

/**
 * Definition of the UserConfigurationDictionaryObjectType type
 */
class UserConfigurationDictionaryObjectType extends EWSType
{
    /**
     * Type property
     *
     * @var string
     */
    public $Type;
    
    /**
     * Value property
     *
     * @var string
     */
    public $Value;
}
