using System;

namespace OpenVsixSignTool.Core
{
    public abstract class ErrorOr<TValue>
    {
        private readonly TValue _value;
        private readonly Error _error;

        private ErrorOr(TValue value) => _value = value;

        private ErrorOr(Error ex) => _error = ex;

        public static implicit operator ErrorOr<TValue>(TValue value) => new Ok(value);
        public static implicit operator ErrorOr<TValue>(Error ex) => new Err(ex);

        public class Ok : ErrorOr<TValue>
        {
            internal Ok(TValue value) : base(value)
            {
            }

            public TValue Value => _value;
        }

        public class Err : ErrorOr<TValue>
        {
            internal Err(Error ex) : base(ex)
            {
            }

            public Error Error => _error;
        }
    }

    public sealed class Error
    {
        public Error(string message) => Message = message;

        public string Message { get; }

        public override string ToString() => Message;

        public static Error From(string message) => new Error(message);
    }
}