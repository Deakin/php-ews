<?php
/**
 * Definition of the GetUserPhotoType type
 *
 * @package php-ews
 * @subpackage Types
 */

namespace PhpEws\EWSType;

/**
 * Default get user photo
 */
class GetUserPhotoType extends EWSType
{   
    /**
     * Email property
     *
     * @var EWSType_Email
     */
    public $Email;

    /**
     * SizeRequested property
     *
     * @var EWSType_UserPhotoSizeType
     */
    public $SizeRequested;
}